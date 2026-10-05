//! HTTP probing with manual redirect chains, per-hop scope checks, and
//! soft-404 detection. Retries transient failures only.

use backon::{ExponentialBuilder, Retryable};
use reqwest::redirect::Policy;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use swiftrecon_scope::ScopeGuard;
use thiserror::Error;
use xxhash_rust::xxh3::xxh3_64;

const MAX_HOPS: usize = 5;
const MAX_BODY_BYTES: usize = 2_097_152;
const EXCERPT_BYTES: usize = 4096;

/// One probed HTTP service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRecord {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub tls: bool,
    pub final_url: String,
    pub chain: Vec<String>,
    pub status: u16,
    pub length: usize,
    pub title: Option<String>,
    pub server: Option<String>,
    pub headers_json: String,
    pub cookie_names: Vec<String>,
    pub cookie_secure_flags: Vec<String>,
    pub content_type: Option<String>,
    pub http_version: String,
    pub time_ms: u64,
    pub body_hash: u64,
    pub excerpt: String,
}

/// Soft-404 shape of one host: the "not found" answer to compare against.
#[derive(Debug, Clone, PartialEq)]
pub struct NotFoundShape {
    pub status: u16,
    pub length: usize,
    pub title: Option<String>,
    pub body_hash: u64,
}

/// A later path is live only when it differs from the not-found shape.
pub fn is_live_path(status: u16, length: usize, body_hash: u64, shape: &NotFoundShape) -> bool {
    if (status == 404 || status == 410) && length == shape.length && body_hash == shape.body_hash {
        return false;
    }
    status != shape.status || length != shape.length || body_hash != shape.body_hash
}

pub fn extract_title(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("title").ok()?;
    document
        .select(&selector)
        .next()
        .map(|el| el.text().collect::<String>().trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Cookie names only (values redacted) plus which flags were present.
pub fn cookie_names(headers: &reqwest::header::HeaderMap) -> (Vec<String>, Vec<String>) {
    let mut names = Vec::new();
    let mut flags = Vec::new();
    for value in headers.get_all(reqwest::header::SET_COOKIE).iter() {
        let text = value.to_str().unwrap_or("").to_string();
        let mut parts = text.split(';');
        if let Some(first) = parts.next() {
            if let Some((name, _)) = first.split_once('=') {
                let name = name.trim().to_string();
                if !name.is_empty() && !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        for flag in ["secure", "httponly", "samesite"] {
            if text.to_lowercase().contains(flag) && !flags.contains(&flag.to_string()) {
                flags.push(flag.to_string());
            }
        }
    }
    names.sort();
    flags.sort();
    (names, flags)
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("out of scope: {0}")]
    OutOfScope(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("too many redirects")]
    TooManyRedirects,
}

#[derive(Debug, Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
}

impl HttpClient {
    pub fn new() -> Result<Self, HttpError> {
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(Policy::none())
            .user_agent("SwiftRecon/0.1 (+local recon)")
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| HttpError::Request(e.to_string()))?;
        Ok(Self { inner })
    }

    async fn get_once(&self, url: &str) -> Result<reqwest::Response, HttpError> {
        (|| async { self.inner.get(url).send().await })
            .retry(ExponentialBuilder::default())
            .await
            .map_err(|e| HttpError::Request(e.to_string()))
    }

    /// GET with retries on transport errors plus 429/5xx (with backoff).
    /// For source fetching (OpenAPI docs, sitemaps, archives) — never for
    /// probes, where every status is data.
    async fn get_resilient(&self, url: &str) -> Result<reqwest::Response, HttpError> {
        (|| async {
            let response = self
                .inner
                .get(url)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status();
            if status.as_u16() == 429 || status.is_server_error() {
                return Err(status.to_string());
            }
            Ok(response)
        })
        .retry(ExponentialBuilder::default())
        .await
        .map_err(HttpError::Request)
    }

    /// Fetch a text document (OpenAPI specs, sitemaps, robots). Scope-checked,
    /// timeout-bounded, size-capped. Non-2xx is an error.
    pub async fn fetch_text(&self, guard: &ScopeGuard, url: &str) -> Result<String, HttpError> {
        if !guard.allow_connection(&url_host(url), None) {
            return Err(HttpError::OutOfScope(url.to_string()));
        }
        let response = self.get_resilient(url).await?;
        if !response.status().is_success() {
            return Err(HttpError::Request(format!("http {}", response.status())));
        }
        let bytes = read_capped(response).await?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Probe one scheme, following redirects manually with a scope check on
    /// every hop. `ip` is the approved resolved address (recorded, not
    /// dialed: reqwest resolves the hostname itself).
    pub async fn probe(
        &self,
        guard: &ScopeGuard,
        host: &str,
        ip: &str,
        port: u16,
        tls: bool,
    ) -> Result<HttpRecord, HttpError> {
        let scheme = if tls { "https" } else { "http" };
        self.probe_url(guard, &format!("{scheme}://{host}:{port}/"), ip)
            .await
    }

    /// Probe a full URL (any path), following redirects manually with a
    /// scope check on every hop.
    pub async fn probe_url(
        &self,
        guard: &ScopeGuard,
        url: &str,
        ip: &str,
    ) -> Result<HttpRecord, HttpError> {
        let parsed = url::Url::parse(url).map_err(|_| HttpError::Request("bad url".to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| HttpError::Request("url has no host".to_string()))?
            .to_string();
        let tls = parsed.scheme() == "https";
        let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
        let mut url = url.to_string();
        let mut chain = Vec::new();
        let start = Instant::now();
        for _ in 0..MAX_HOPS {
            if !guard.allow_connection(&url_host(&url), None) {
                return Err(HttpError::OutOfScope(url));
            }
            chain.push(url.clone());
            let response = self.get_once(&url).await?;
            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                if location.is_empty() {
                    return Err(HttpError::Request("empty redirect location".to_string()));
                }
                url = join_url(&url, &location);
                continue;
            }
            return record_response(
                &host,
                ip,
                port,
                tls,
                PendingFetch {
                    url,
                    chain,
                    response,
                    start,
                },
            )
            .await;
        }
        Err(HttpError::TooManyRedirects)
    }
}

struct PendingFetch {
    url: String,
    chain: Vec<String>,
    response: reqwest::Response,
    start: Instant,
}

async fn record_response(
    host: &str,
    ip: &str,
    port: u16,
    tls: bool,
    fetch: PendingFetch,
) -> Result<HttpRecord, HttpError> {
    let PendingFetch {
        url,
        chain,
        response,
        start,
    } = fetch;
    let status = response.status().as_u16();
    let version = format!("{:?}", response.version());
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let server = response
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let headers_json =
        serde_json::to_string(&header_map(&response)).unwrap_or_else(|_| "{}".to_string());
    let (cookie_names, cookie_flags) = cookie_names(response.headers());
    // Body reads get an explicit timeout: reqwest's request timeout does
    // not cover streaming, and a hostile server can hold the body open.
    // Chunks are capped as they arrive: a decompression bomb expands in
    // memory during decode, so a post-decode cap alone is not enough.
    let bytes = read_capped(response).await?;
    let capped = &bytes[..bytes.len().min(MAX_BODY_BYTES)];
    let text = String::from_utf8_lossy(capped).into_owned();
    Ok(HttpRecord {
        host: host.to_string(),
        ip: ip.to_string(),
        port,
        tls,
        final_url: url,
        chain,
        status,
        length: capped.len(),
        title: extract_title(&text),
        server,
        headers_json,
        cookie_names,
        cookie_secure_flags: cookie_flags,
        content_type,
        http_version: version,
        time_ms: start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        body_hash: xxh3_64(capped),
        excerpt: text.chars().take(EXCERPT_BYTES).collect(),
    })
}

impl HttpClient {
    /// Fetch the not-found shape: GET a random path that cannot exist.
    pub async fn not_found_shape(
        &self,
        guard: &ScopeGuard,
        host: &str,
        _ip: &str,
        port: u16,
        tls: bool,
    ) -> Option<NotFoundShape> {
        let scheme = if tls { "https" } else { "http" };
        let nonce = Instant::now().elapsed().as_nanos();
        let url = format!("{scheme}://{host}:{port}/swr-nonexistent-{nonce}");
        if !guard.allow_connection(&url_host(&url), None) {
            return None;
        }
        let response = self.get_once(&url).await.ok()?;
        if response.status().is_redirection() {
            return None;
        }
        let status = response.status().as_u16();
        let bytes = match read_capped(response).await {
            Ok(bytes) => bytes,
            Err(_) => return None,
        };
        let capped = &bytes[..bytes.len().min(MAX_BODY_BYTES)];
        let text = String::from_utf8_lossy(capped);
        Some(NotFoundShape {
            status,
            length: capped.len(),
            title: extract_title(&text),
            body_hash: xxh3_64(capped),
        })
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new().expect("reqwest client builds with static config")
    }
}

/// Read a response body with a timeout and a running size cap.
async fn read_capped(mut response: reqwest::Response) -> Result<Vec<u8>, HttpError> {
    let mut kept: Vec<u8> = Vec::new();
    let streamed = async {
        while kept.len() < MAX_BODY_BYTES {
            match response.chunk().await {
                Ok(Some(chunk)) => kept.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => return Err(HttpError::Request(e.to_string())),
            }
        }
        Ok(kept)
    };
    tokio::time::timeout(Duration::from_secs(30), streamed)
        .await
        .map_err(|_| HttpError::Request("body read timed out".to_string()))?
}

fn url_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default()
}

fn join_url(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
    match url::Url::parse(base).and_then(|b| b.join(location)) {
        Ok(joined) => joined.to_string(),
        Err(_) => location.to_string(),
    }
}

fn header_map(response: &reqwest::Response) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for (name, value) in response.headers().iter() {
        if map.len() >= 100 {
            break;
        }
        if let Ok(text) = value.to_str() {
            map.entry(name.to_string()).or_insert_with(|| {
                if name.as_str().eq_ignore_ascii_case("set-cookie") {
                    "[redacted]".to_string()
                } else {
                    text.chars().take(1024).collect()
                }
            });
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_extraction() {
        assert_eq!(
            extract_title("<html><head><title> Hello </title></head></html>"),
            Some("Hello".to_string())
        );
        assert_eq!(extract_title("<html><body>no title</body></html>"), None);
    }

    #[test]
    fn live_path_detection() {
        let shape = NotFoundShape {
            status: 404,
            length: 100,
            title: None,
            body_hash: 42,
        };
        assert!(!is_live_path(404, 100, 42, &shape));
        assert!(is_live_path(200, 100, 42, &shape));
        assert!(is_live_path(404, 150, 43, &shape));
    }

    #[test]
    fn relative_redirects_join() {
        assert_eq!(
            join_url("http://a.test:8080/x/", "/y"),
            "http://a.test:8080/y".to_string()
        );
        assert_eq!(
            join_url("http://a.test/", "https://b.test/z"),
            "https://b.test/z".to_string()
        );
    }

    /// Live probe against a loopback fixture server (real socket, real HTTP).
    #[tokio::test]
    async fn live_loopback_probe() {
        use swiftrecon_scope::{Scope, ScopeGuard};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let _ = socket.read(&mut buf).await;
                let body = "<html><head><title>Lab</title></head></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nServer: LabServer/1.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        let guard = ScopeGuard::new(Scope::from_lists(&["127.0.0.1".to_string()], &[]).unwrap());
        let client = HttpClient::new().unwrap();
        let record = client
            .probe(&guard, "127.0.0.1", "127.0.0.1", port, false)
            .await
            .expect("loopback probe succeeds");
        assert_eq!(record.status, 200);
        assert_eq!(record.title, Some("Lab".to_string()));
        assert_eq!(record.server, Some("LabServer/1.0".to_string()));
        assert!(record.body_hash != 0);
    }
}
