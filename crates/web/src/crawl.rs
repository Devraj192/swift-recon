//! Polite same-scope crawler: depth limit, per-host politeness and caps,
//! crawler-trap protection via path-template collapsing, robots/sitemap
//! discovery (parse-only by default, never a block list).

use scraper::{Html, Selector};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use swiftrecon_engine::AdaptiveLimiter;
use swiftrecon_net::http::HttpClient;
use swiftrecon_net::{DnsOutcome, ResolverPool};
use swiftrecon_scope::ScopeGuard;

use crate::url::{canonicalize, template_path};

/// Knobs for the crawl. Every option is used by `crawl` below.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub max_depth: u32,
    pub max_urls_per_host: usize,
    pub max_pages_total: usize,
    pub politeness_ms: u64,
    pub respect_robots: bool,
    pub trap_threshold: usize,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_urls_per_host: 100,
            max_pages_total: 1000,
            politeness_ms: 200,
            respect_robots: false,
            trap_threshold: 20,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Page {
    pub url: String,
    pub depth: u32,
    pub links: Vec<String>,
    pub scripts: Vec<String>,
    pub iframes: Vec<String>,
    pub forms: Vec<Form>,
    pub inline_scripts: Vec<String>,
    pub title: Option<String>,
}

/// Extract page features from HTML. Pure function, unit-tested.
pub fn extract_features(base_url: &str, html: &str) -> Page {
    let document = Html::parse_document(html);
    let base = url::Url::parse(base_url);
    let mut page = Page {
        url: base_url.to_string(),
        depth: 0,
        links: Vec::new(),
        scripts: Vec::new(),
        iframes: Vec::new(),
        forms: Vec::new(),
        inline_scripts: Vec::new(),
        title: swiftrecon_net::http::extract_title(html),
    };
    let resolve = |raw: &str| -> Option<String> {
        let base = base.as_ref().ok()?;
        base.join(raw.trim()).ok().map(|u| u.to_string())
    };
    if let Ok(selector) = Selector::parse("a[href], link[href]") {
        for el in document.select(&selector) {
            if let Some(href) = el.attr("href") {
                if let Some(abs) = resolve(href) {
                    page.links.push(abs);
                }
            }
        }
    }
    if let Ok(selector) = Selector::parse("script[src]") {
        for el in document.select(&selector) {
            if let Some(src) = el.attr("src") {
                if let Some(abs) = resolve(src) {
                    page.scripts.push(abs);
                }
            }
        }
    }
    if let Ok(selector) = Selector::parse("script:not([src])") {
        for el in document.select(&selector) {
            let text: String = el.text().collect();
            if !text.trim().is_empty() {
                page.inline_scripts.push(text);
            }
        }
    }
    if let Ok(selector) = Selector::parse("iframe[src]") {
        for el in document.select(&selector) {
            if let Some(src) = el.attr("src") {
                if let Some(abs) = resolve(src) {
                    page.iframes.push(abs);
                }
            }
        }
    }
    if let Ok(selector) = Selector::parse("form") {
        for el in document.select(&selector) {
            let action = el
                .attr("action")
                .and_then(resolve)
                .unwrap_or_else(|| base_url.to_string());
            let method = el.attr("method").unwrap_or("GET").to_uppercase();
            let mut inputs = Vec::new();
            if let Ok(input_sel) = Selector::parse("input[name], select[name], textarea[name]") {
                for input in el.select(&input_sel) {
                    if let Some(name) = input.attr("name") {
                        if !name.is_empty() {
                            inputs.push(name.to_string());
                        }
                    }
                }
            }
            inputs.sort();
            inputs.dedup();
            page.forms.push(Form {
                action,
                method,
                inputs,
            });
        }
    }
    page.links.sort();
    page.links.dedup();
    page.scripts.sort();
    page.scripts.dedup();
    page
}

/// Parse robots.txt into (disallow paths, sitemap URLs). Discovery only.
pub fn parse_robots(text: &str) -> (Vec<String>, Vec<String>) {
    let mut disallow = Vec::new();
    let mut sitemaps = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            match key.trim().to_lowercase().as_str() {
                "disallow" => {
                    let path = value.trim().to_string();
                    if !path.is_empty() {
                        disallow.push(path);
                    }
                }
                "sitemap" => {
                    let url = value.trim().to_string();
                    if !url.is_empty() {
                        sitemaps.push(url);
                    }
                }
                _ => {}
            }
        }
    }
    (disallow, sitemaps)
}

/// Parse sitemap XML `<loc>` URLs.
pub fn parse_sitemap(xml: &str) -> Vec<String> {
    let document = Html::parse_document(xml);
    let mut urls = Vec::new();
    if let Ok(selector) = Selector::parse("loc") {
        for el in document.select(&selector) {
            let text: String = el.text().collect();
            let text = text.trim().to_string();
            if !text.is_empty() {
                urls.push(text);
            }
        }
    }
    urls.sort();
    urls.dedup();
    urls
}

fn url_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

/// Crawl from seeds. Every fetched URL passes the scope guard; per-host
/// politeness sleeps between hits; templates repeating past the trap
/// threshold are skipped (calendar-style infinite traps). URLs in
/// `completed` (already crawled by an interrupted run) are skipped without
/// fetching, which is what makes kill-and-resume exact.
pub async fn crawl(
    client: &HttpClient,
    pool: &ResolverPool,
    guard: &ScopeGuard,
    limiter: &AdaptiveLimiter,
    seeds: &[String],
    completed: &HashSet<String>,
    config: &CrawlConfig,
) -> Vec<Page> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut per_host_count: HashMap<String, usize> = HashMap::new();
    let mut per_host_last: HashMap<String, Instant> = HashMap::new();
    let mut template_hits: HashMap<String, usize> = HashMap::new();
    let mut queue: Vec<(String, u32)> = seeds
        .iter()
        .filter_map(|s| canonicalize(s).map(|u| (u, 0)))
        .collect();
    let mut pages = Vec::new();

    while let Some((url, depth)) = queue.pop() {
        if pages.len() >= config.max_pages_total || !visited.insert(url.clone()) {
            continue;
        }
        if completed.contains(&url) {
            continue;
        }
        let Some(host) = url_host(&url) else { continue };
        if !guard.allow_dns(&host) {
            continue;
        }
        let host_count = per_host_count.entry(host.clone()).or_insert(0);
        if *host_count >= config.max_urls_per_host {
            continue;
        }
        *host_count += 1;
        // Crawler-trap protection: collapse repeating path patterns.
        let path = url::Url::parse(&url)
            .map(|u| u.path().to_string())
            .unwrap_or_default();
        let trap_key = format!("{host}{}", template_path(&path));
        let trap_count = template_hits.entry(trap_key).or_insert(0);
        *trap_count += 1;
        if *trap_count > config.trap_threshold {
            continue;
        }
        // Per-host politeness.
        if let Some(last) = per_host_last.get(&host) {
            let wait = Duration::from_millis(config.politeness_ms)
                .checked_sub(last.elapsed())
                .unwrap_or_default();
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        per_host_last.insert(host.clone(), Instant::now());
        // IP literals need no DNS round-trip; hostnames resolve via the pool.
        let _ip = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => match pool.resolve(guard, &host).await {
                Some(DnsOutcome::Answered { mut ips, .. }) if !ips.is_empty() => {
                    ips.swap_remove(0).to_string()
                }
                _ => continue,
            },
        };
        if url::Url::parse(&url).is_err() {
            continue;
        }
        limiter.pause().await;
        let record = match client.probe_url(guard, &url, &_ip).await {
            Ok(record) => {
                if record.status == 429 || (500..600).contains(&record.status) {
                    limiter.note_failure();
                } else {
                    limiter.note_success();
                }
                record
            }
            Err(_) => {
                limiter.note_failure();
                continue;
            }
        };
        let content_html = record
            .content_type
            .as_deref()
            .map(|ct| ct.contains("html"))
            .unwrap_or(true);
        if !content_html {
            continue;
        }
        let mut page = extract_features(&url, &record.excerpt);
        page.depth = depth;
        page.title = record.title.clone();
        if depth < config.max_depth {
            for link in page
                .links
                .iter()
                .chain(page.scripts.iter())
                .chain(page.iframes.iter())
            {
                if let Some(canonical) = canonicalize(link) {
                    queue.push((canonical, depth + 1));
                }
            }
        }
        pages.push(page);
    }
    pages
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTML: &str = r#"<html><head><title>T</title></head><body>
<a href="/a">a</a><a href="https://other.test/b">b</a>
<script src="/app.js"></script><script>fetch('/api/x')</script>
<iframe src="/frame"></iframe>
<form action="/login" method="post"><input name="user"><input name="pass"></form>
</body></html>"#;

    #[test]
    fn features_extracted_and_resolved() {
        let page = extract_features("http://a.test/base/", HTML);
        assert!(page.links.contains(&"http://a.test/a".to_string()));
        assert!(page.links.contains(&"https://other.test/b".to_string()));
        assert_eq!(page.scripts, vec!["http://a.test/app.js".to_string()]);
        assert_eq!(page.iframes, vec!["http://a.test/frame".to_string()]);
        assert_eq!(page.inline_scripts.len(), 1);
        assert!(page.inline_scripts[0].contains("fetch"));
        assert_eq!(page.forms.len(), 1);
        assert_eq!(page.forms[0].action, "http://a.test/login".to_string());
        assert_eq!(page.forms[0].method, "POST".to_string());
        assert_eq!(
            page.forms[0].inputs,
            vec!["pass".to_string(), "user".to_string()]
        );
    }

    #[test]
    fn robots_parsed() {
        let (disallow, sitemaps) = parse_robots(
            "# comment\nUser-agent: *\nDisallow: /admin\nSitemap: https://a.test/sitemap.xml\n",
        );
        assert_eq!(disallow, vec!["/admin".to_string()]);
        assert_eq!(sitemaps, vec!["https://a.test/sitemap.xml".to_string()]);
    }

    #[test]
    fn sitemap_locs_extracted() {
        let urls = parse_sitemap(
            "<?xml version=\"1.0\"?><urlset><url><loc>https://a.test/x</loc></url></urlset>",
        );
        assert_eq!(urls, vec!["https://a.test/x".to_string()]);
    }

    /// Phase 4 exit gate: kill-and-resume. A loopback server counts hits;
    /// the second run with completed URLs must fetch nothing new.
    #[tokio::test]
    async fn kill_and_resume_skips_completed() {
        use std::sync::{Arc, Mutex};
        use swiftrecon_engine::AdaptiveLimiter;
        use swiftrecon_net::http::HttpClient;
        use swiftrecon_net::ResolverPool;
        use swiftrecon_scope::{Scope, ScopeGuard};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let hits: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_hits = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let hits = server_hits.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let request = String::from_utf8_lossy(&buf);
                    let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                    *hits.lock().unwrap().entry(path.clone()).or_insert(0) += 1;
                    let body = format!(
                        "<html><head><title>{path}</title></head><body>\
                         <a href=\"/a\">a</a><a href=\"/b\">b</a><a href=\"/\">root</a></body></html>"
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });

        let guard = ScopeGuard::new(Scope::from_lists(&["127.0.0.1".to_string()], &[]).unwrap());
        let pool = ResolverPool::new(1, 50);
        let client = HttpClient::new().unwrap();
        let limiter = AdaptiveLimiter::new(Duration::from_millis(0));
        let config = CrawlConfig {
            max_depth: 5,
            max_urls_per_host: 10,
            max_pages_total: 100,
            politeness_ms: 0,
            respect_robots: false,
            trap_threshold: 100,
        };
        let root = format!("http://127.0.0.1:{port}/");
        let empty: HashSet<String> = HashSet::new();
        let first = crawl(
            &client,
            &pool,
            &guard,
            &limiter,
            std::slice::from_ref(&root),
            &empty,
            &config,
        )
        .await;
        assert_eq!(first.len(), 3);
        let hits_after_first = hits.lock().unwrap().values().sum::<usize>();
        assert!(hits_after_first >= 3);

        // "Kill": completed set holds everything the first run saved.
        let completed: HashSet<String> = first.iter().map(|p| p.url.clone()).collect();
        let second = crawl(
            &client,
            &pool,
            &guard,
            &limiter,
            std::slice::from_ref(&root),
            &completed,
            &config,
        )
        .await;
        assert!(second.is_empty());
        let hits_after_second = hits.lock().unwrap().values().sum::<usize>();
        assert_eq!(hits_after_second, hits_after_first);

        // Partial resume: a completed sibling is not refetched while the
        // missing one is. (Completed pages are not expanded: without
        // fetching, their links are unknown — the frontier restarts
        // from seeds and skips exactly the saved units.)
        let mut partial = HashSet::new();
        partial.insert(format!("http://127.0.0.1:{port}/a"));
        let before_a = hits.lock().unwrap().get("/a").copied().unwrap_or(0);
        let before_b = hits.lock().unwrap().get("/b").copied().unwrap_or(0);
        let third = crawl(&client, &pool, &guard, &limiter, &[root], &partial, &config).await;
        assert!(third.iter().any(|p| p.url.ends_with("/b")));
        let after_a = hits.lock().unwrap().get("/a").copied().unwrap_or(0);
        let after_b = hits.lock().unwrap().get("/b").copied().unwrap_or(0);
        assert_eq!(after_a, before_a);
        assert_eq!(after_b, before_b + 1);
    }

    #[test]
    fn lab_spa_endpoint_param_recall() {
        use crate::js::analyze;
        use crate::url::{canonicalize, query_params, template_path};
        use std::collections::HashSet;

        let base = "http://spa.test";
        let index = include_str!("../../../lab/spa/index.html");
        let app_js = include_str!("../../../lab/spa/app.js");
        let page = extract_features(&format!("{base}/"), index);
        let app = analyze(app_js);
        let mut js_urls = app.urls;
        let mut js_params = app.params;
        for inline in &page.inline_scripts {
            let found = analyze(inline);
            js_urls.extend(found.urls);
            js_params.extend(found.params);
        }

        let mut endpoints: HashSet<String> = HashSet::new();
        let mut params: HashSet<String> = js_params.into_iter().collect();
        let mut sources = page.links.clone();
        sources.extend(page.scripts.clone());
        // JS-found paths are often relative: resolve against the base first.
        sources.extend(
            js_urls
                .iter()
                .filter_map(|u| crate::url::resolve_against(base, u)),
        );
        for form in &page.forms {
            sources.push(form.action.clone());
            params.extend(form.inputs.iter().cloned());
        }
        for raw in &sources {
            if let Some(canonical) = canonicalize(raw) {
                if let Ok(url) = url::Url::parse(&canonical) {
                    endpoints.insert(template_path(url.path()));
                }
                for param in query_params(&canonical, "spa") {
                    params.insert(param.name);
                }
            }
        }

        let truth_endpoints: HashSet<&str> = [
            "/about",
            "/contact",
            "/static/app.js",
            "/api/v1/users",
            "/api/v1/orders",
            "/api/v1/login",
            "/api/v1/users/{id}",
        ]
        .into_iter()
        .collect();
        let truth_params: HashSet<&str> = ["role", "limit", "verbose", "user", "pass"]
            .into_iter()
            .collect();
        let endpoint_recall = truth_endpoints
            .iter()
            .filter(|e| endpoints.contains(**e))
            .count() as f64
            / truth_endpoints.len() as f64;
        let param_recall = truth_params.iter().filter(|p| params.contains(**p)).count() as f64
            / truth_params.len() as f64;
        eprintln!("lab spa: endpoint_recall={endpoint_recall:.4} param_recall={param_recall:.4}");
        assert!(endpoint_recall >= 0.85, "endpoints: {endpoints:?}");
        assert!(param_recall >= 0.85, "params: {params:?}");
    }
}
