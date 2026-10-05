//! OpenAPI/Swagger discovery, historical URLs (Wayback CDX), and
//! robots/sitemap fetching. Pure parsing is unit-testable without network.

use std::collections::HashSet;
use swiftrecon_net::http::HttpClient;
use swiftrecon_scope::ScopeGuard;

/// Well-known OpenAPI document paths (PRD FR-10).
const OPENAPI_PATHS: &[&str] = &["/openapi.json", "/swagger.json", "/v3/api-docs"];

/// One endpoint from any source.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub path: String,
    pub methods: Vec<String>,
    pub sources: Vec<String>,
}

/// Parse an OpenAPI/Swagger document into (path, methods).
pub fn parse_openapi(text: &str) -> Vec<Endpoint> {
    let doc: serde_json::Value = match serde_json::from_str(text) {
        Ok(doc) => doc,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(paths) = doc.get("paths").and_then(|p| p.as_object()) {
        for (path, item) in paths {
            let mut methods: Vec<String> = item
                .as_object()
                .map(|obj| {
                    obj.keys()
                        .filter(|k| {
                            matches!(
                                k.to_lowercase().as_str(),
                                "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
                            )
                        })
                        .map(|k| k.to_uppercase())
                        .collect()
                })
                .unwrap_or_default();
            methods.sort();
            methods.dedup();
            out.push(Endpoint {
                path: path.clone(),
                methods,
                sources: vec!["openapi".to_string()],
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Parse Wayback CDX JSON (`[[\"original\"],[\"url\"...]]`) into URLs.
pub fn parse_wayback(text: &str) -> Vec<String> {
    let rows: Vec<Vec<String>> = match serde_json::from_str(text) {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for row in rows {
        if let Some(url) = row.first() {
            if url != "original" && !url.is_empty() {
                out.push(url.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn join_base(base: &str, path: &str) -> Option<String> {
    url::Url::parse(base)
        .and_then(|b| b.join(path))
        .ok()
        .map(|u| u.to_string())
}

/// Fetch well-known OpenAPI docs under `base` (e.g. https://host:port).
/// Missing docs are skipped silently; fetch failures return empty.
pub async fn discover_openapi(
    client: &HttpClient,
    guard: &ScopeGuard,
    base: &str,
) -> Vec<Endpoint> {
    let mut out = Vec::new();
    for path in OPENAPI_PATHS {
        let Some(url) = join_base(base, path) else {
            continue;
        };
        let Ok(text) = client.fetch_text(guard, &url).await else {
            continue;
        };
        for mut endpoint in parse_openapi(&text) {
            // Resolve relative doc paths against the base.
            if let Some(absolute) = join_base(base, &endpoint.path) {
                endpoint.path = absolute;
            }
            out.push(endpoint);
        }
    }
    out
}

/// Historical URLs from the Wayback CDX API (passive, third-party).
pub async fn wayback_urls(client: &HttpClient, guard: &ScopeGuard, domain: &str) -> Vec<String> {
    // web.archive.org must pass the guard like any other outbound host.
    if !guard.allow_dns("web.archive.org") {
        return Vec::new();
    }
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
    );
    match client.fetch_text(guard, &url).await {
        Ok(text) => parse_wayback(&text),
        Err(_) => Vec::new(),
    }
}

/// robots.txt discovery for one host: disallow paths as endpoint hints plus
/// sitemap URLs and their contents.
pub async fn robots_endpoints(
    client: &HttpClient,
    guard: &ScopeGuard,
    base: &str,
) -> (Vec<String>, Vec<String>) {
    let Some(robots_url) = join_base(base, "/robots.txt") else {
        return (Vec::new(), Vec::new());
    };
    let Ok(text) = client.fetch_text(guard, &robots_url).await else {
        return (Vec::new(), Vec::new());
    };
    let (disallow, sitemaps) = crate::crawl::parse_robots(&text);
    let mut paths: Vec<String> = disallow.iter().filter_map(|p| join_base(base, p)).collect();
    let mut seen: HashSet<String> = sitemaps.iter().cloned().collect();
    let mut urls: Vec<String> = Vec::new();
    for sitemap in &sitemaps {
        let Ok(xml) = client.fetch_text(guard, sitemap).await else {
            continue;
        };
        for url in crate::crawl::parse_sitemap(&xml) {
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }
    }
    paths.sort();
    paths.dedup();
    (paths, urls)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str =
        r#"{"openapi":"3.0.0","paths":{"/users/{id}":{"get":{},"post":{}},"/health":{"get":{}}}}"#;

    #[test]
    fn openapi_paths_and_methods() {
        let endpoints = parse_openapi(SPEC);
        assert_eq!(endpoints.len(), 2);
        let users = endpoints.iter().find(|e| e.path == "/users/{id}").unwrap();
        assert_eq!(users.methods, vec!["GET".to_string(), "POST".to_string()]);
        assert!(parse_openapi("garbage").is_empty());
    }

    #[test]
    fn wayback_rows_parsed() {
        let text = r#"[["original"],["https://a.test/x?b=1"],["https://a.test/x?b=1"]]"#;
        assert_eq!(
            parse_wayback(text),
            vec!["https://a.test/x?b=1".to_string()]
        );
        assert!(parse_wayback("nope").is_empty());
    }
}
