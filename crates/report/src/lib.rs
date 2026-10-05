//! Report rendering: canonical JSON, CSV, and single-file offline HTML.
//! All target-controlled text is escaped; the HTML report carries a strict
//! CSP and no external assets.

use minijinja::{context, Environment};
use serde::{Deserialize, Serialize};
use swiftrecon_net::http::HttpRecord;
use swiftrecon_net::tls::TlsRecord;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRow {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub state: String,
    pub reason: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechRow {
    pub host: String,
    pub name: String,
    pub version: Option<String>,
    pub confidence: f64,
    pub evidence_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRow {
    pub template: String,
    pub methods: Vec<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamRow {
    pub endpoint: String,
    pub name: String,
    pub location: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub targets: Vec<String>,
    pub subdomains: Vec<String>,
    pub ports: Vec<PortRow>,
    pub http: Vec<HttpRecord>,
    pub tls: Vec<TlsRecord>,
    pub technologies: Vec<TechRow>,
    pub endpoints: Vec<EndpointRow>,
    pub parameters: Vec<ParamRow>,
}

/// Canonical JSON (pretty). Machine consumers read this or JSONL.
pub fn to_json(report: &ScanReport) -> Result<String, ReportError> {
    serde_json::to_string_pretty(report).map_err(|e| ReportError::Render(e.to_string()))
}

/// Fixed-column CSV of ports (RFC 4180 quoting via manual escaping).
pub fn ports_csv(report: &ScanReport) -> String {
    let mut out = String::from("scan_id,host,ip,port,state,reason,latency_ms\n");
    for row in &report.ports {
        out.push_str(&csv_line(&[
            &report.scan_id,
            &row.host,
            &row.ip,
            &row.port.to_string(),
            &row.state,
            &row.reason,
            &row.latency_ms.to_string(),
        ]));
    }
    out
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_line(fields: &[&str]) -> String {
    let mut line = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    line.push('\n');
    line
}

const HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SwiftRecon {{ scan_id }}</title>
<style>body{font-family:sans-serif;max-width:60em;margin:2em auto;padding:0 1em}table{border-collapse:collapse;width:100%}th,td{border:1px solid #999;padding:.3em .5em;text-align:left}th{background:#eee}</style>
</head>
<body>
<h1>SwiftRecon {{ scan_id }}</h1>
<p>Targets: {{ targets|join(", ") }}. Subdomains: {{ subdomains|length }}. Open ports: {{ open_count }}.</p>
<h2>Subdomains</h2>
<ul>{% for host in subdomains %}<li>{{ host }}</li>{% endfor %}</ul>
<h2>Ports</h2>
<table><tr><th>Host</th><th>IP</th><th>Port</th><th>State</th><th>Reason</th></tr>
{% for row in ports %}<tr><td>{{ row.host }}</td><td>{{ row.ip }}</td><td>{{ row.port }}</td><td>{{ row.state }}</td><td>{{ row.reason }}</td></tr>{% endfor %}</table>
<h2>Technologies</h2>
<table><tr><th>Host</th><th>Name</th><th>Version</th><th>Confidence</th></tr>
{% for tech in technologies %}<tr><td>{{ tech.host }}</td><td>{{ tech.name }}</td><td>{{ tech.version }}</td><td>{{ tech.confidence }}</td></tr>{% endfor %}</table>
<h2>TLS</h2>
<table><tr><th>Host</th><th>Port</th><th>Version</th><th>Subject</th><th>Expired</th></tr>
{% for record in tls %}<tr><td>{{ record.host }}</td><td>{{ record.port }}</td><td>{{ record.version }}</td><td>{{ record.subject }}</td><td>{{ record.expired }}</td></tr>{% endfor %}</table>
<h2>Endpoints</h2>
<table><tr><th>Template</th><th>Methods</th><th>Sources</th></tr>
{% for endpoint in endpoints %}<tr><td>{{ endpoint.template }}</td><td>{{ endpoint.methods|join(", ") }}</td><td>{{ endpoint.sources|join(", ") }}</td></tr>{% endfor %}</table>
<h2>Parameters</h2>
<table><tr><th>Endpoint</th><th>Name</th><th>Location</th><th>Method</th></tr>
{% for param in parameters %}<tr><td>{{ param.endpoint }}</td><td>{{ param.name }}</td><td>{{ param.location }}</td><td>{{ param.method }}</td></tr>{% endfor %}</table>
</body>
</html>
"#;

/// Single-file HTML. minijinja auto-escapes `{{ }}` for `.html` templates.
pub fn to_html(report: &ScanReport) -> Result<String, ReportError> {
    let mut env = Environment::new();
    env.add_template("report.html", HTML_TEMPLATE)
        .map_err(|e| ReportError::Render(e.to_string()))?;
    let template = env
        .get_template("report.html")
        .map_err(|e| ReportError::Render(e.to_string()))?;
    let open_count = report.ports.iter().filter(|r| r.state == "open").count();
    template
        .render(context! {
            scan_id => report.scan_id,
            targets => report.targets,
            subdomains => report.subdomains,
            ports => report.ports,
            technologies => report.technologies,
            tls => report.tls,
            endpoints => report.endpoints,
            parameters => report.parameters,
            open_count => open_count,
        })
        .map_err(|e| ReportError::Render(e.to_string()))
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("render error: {0}")]
    Render(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ScanReport {
        ScanReport {
            scan_id: "scan1".to_string(),
            targets: vec!["example.com".to_string()],
            subdomains: vec!["a.example.com".to_string()],
            ports: vec![PortRow {
                host: "a.example.com".to_string(),
                ip: "1.2.3.4".to_string(),
                port: 80,
                state: "open".to_string(),
                reason: "handshake".to_string(),
                latency_ms: 3,
            }],
            http: Vec::new(),
            tls: Vec::new(),
            technologies: vec![TechRow {
                host: "a.example.com".to_string(),
                name: "nginx".to_string(),
                version: None,
                confidence: 0.7,
                evidence_count: 1,
            }],
            endpoints: vec![EndpointRow {
                template: "http://a.example.com/users/{id}".to_string(),
                methods: vec!["GET".to_string()],
                sources: vec!["crawler".to_string()],
            }],
            parameters: vec![ParamRow {
                endpoint: "http://a.example.com/users/{id}".to_string(),
                name: "verbose".to_string(),
                location: "query".to_string(),
                method: "GET".to_string(),
            }],
        }
    }

    #[test]
    fn json_round_trips() {
        let json = to_json(&sample()).unwrap();
        let parsed: ScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scan_id, "scan1");
        assert_eq!(parsed.ports.len(), 1);
    }

    #[test]
    fn csv_has_header_and_quoting() {
        let csv = ports_csv(&sample());
        assert!(csv.starts_with("scan_id,host,ip,port,state,reason,latency_ms\n"));
        assert!(csv.contains("scan1,a.example.com,1.2.3.4,80,open,handshake,3\n"));
        assert_eq!(csv_field("a,b\"c"), "\"a,b\"\"c\"");
    }

    #[test]
    fn html_escapes_hostile_text() {
        let mut report = sample();
        report.subdomains = vec!["<script>alert(1)</script>".to_string()];
        let html = to_html(&report).unwrap();
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("Content-Security-Policy"));
    }
}
