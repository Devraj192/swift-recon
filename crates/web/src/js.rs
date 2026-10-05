//! JavaScript analysis: AST string/call extraction with regex fallback.
//!
//! Each unique file is hashed so it is parsed once. Secret-like matches
//! store only the KIND (never the value). Confidence is lower when the
//! regex fallback ran instead of the AST.

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    CallExpression, Expression, StaticMemberExpression, StringLiteral, TemplateLiteral,
};
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default)]
pub struct JsFinding {
    pub urls: Vec<String>,
    pub calls: Vec<String>,
    pub params: Vec<String>,
    pub websockets: Vec<String>,
    pub sourcemap: Option<String>,
    pub secret_kinds: Vec<String>,
    pub parsed_ok: bool,
}

struct Collector {
    strings: Vec<String>,
    calls: Vec<String>,
}

impl<'a> Visit<'a> for Collector {
    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        self.strings.push(it.value.as_str().to_string());
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        for quasi in &it.quasis {
            if let Some(cooked) = &quasi.value.cooked {
                self.strings.push(cooked.as_str().to_string());
            }
        }
        for expression in it.expressions.iter() {
            self.visit_expression(expression);
        }
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Some(name) = callee_name(&it.callee) {
            self.calls.push(name);
        }
        self.visit_expression(&it.callee);
        for argument in it.arguments.iter() {
            self.visit_argument(argument);
        }
    }
}

fn callee_name(callee: &Expression<'_>) -> Option<String> {
    match callee {
        Expression::Identifier(id) => Some(id.name.as_str().to_string()),
        Expression::StaticMemberExpression(member) => {
            let member: &StaticMemberExpression<'_> = member;
            let object = match &member.object {
                Expression::Identifier(id) => id.name.as_str().to_string(),
                _ => return None,
            };
            Some(format!("{}.{}", object, member.property.name.as_str()))
        }
        _ => None,
    }
}

fn looks_like_url(s: &str) -> bool {
    let lower = s.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return true;
    }
    if s.starts_with("//") {
        return s.len() > 2;
    }
    if s.starts_with('/') {
        return s.len() > 1;
    }
    false
}

fn looks_like_ws(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.starts_with("ws://") || lower.starts_with("wss://")
}

/// Param names from query strings inside a literal (`?a=1&b=2`).
fn params_in(s: &str) -> Vec<String> {
    let query = match s.split_once('?') {
        Some((_, query)) => query,
        None => return Vec::new(),
    };
    query
        .split('&')
        .filter_map(|pair| pair.split_once('=').map(|(k, _)| k.trim().to_string()))
        .filter(|k| {
            !k.is_empty()
                && k.chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        })
        .collect()
}

fn secret_regexes() -> &'static Vec<(String, Regex)> {
    static PATTERNS: OnceLock<Vec<(String, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (
                "aws_key".to_string(),
                Regex::new("AKIA[0-9A-Z]{16}").expect("static regex"),
            ),
            (
                "generic_secret".to_string(),
                Regex::new("(?i)(api[_-]?key|secret|token)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]")
                    .expect("static regex"),
            ),
        ]
    })
}

fn string_literal_regex() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new("\"([^\"\\\\]|\\\\.)*\"|'([^'\\\\]|\\\\.)*'|`([^`\\\\]|\\\\.)*`")
            .expect("static regex")
    })
}

fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        if (bytes[0] == b'"' || bytes[0] == b'\'' || bytes[0] == b'`')
            && bytes[s.len() - 1] == bytes[0]
        {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Regex fallback over raw source. Lower confidence than the AST path.
fn regex_extract(source: &str, strings: &mut Vec<String>) {
    for mat in string_literal_regex().find_iter(source) {
        strings.push(strip_quotes(mat.as_str()).to_string());
    }
}

/// Classify collected strings into urls/params/websockets/secrets.
fn classify(strings: Vec<String>, finding: &mut JsFinding) {
    let mut urls = HashSet::new();
    let mut params = HashSet::new();
    let mut websockets = HashSet::new();
    for s in &strings {
        if looks_like_ws(s) {
            websockets.insert(s.clone());
        } else if looks_like_url(s) {
            urls.insert(s.clone());
        }
        for param in params_in(s) {
            params.insert(param);
        }
    }
    let mut secret_kinds = HashSet::new();
    for (kind, regex) in secret_regexes().iter() {
        if strings.iter().any(|s| regex.is_match(s)) {
            secret_kinds.insert(kind.clone());
        }
    }
    finding.urls = sorted(urls);
    finding.params = sorted(params);
    finding.websockets = sorted(websockets);
    finding.secret_kinds = sorted(secret_kinds);
}

fn sorted(set: HashSet<String>) -> Vec<String> {
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort();
    out
}

/// Analyze one JS source. AST first; regex fallback merged when parsing
/// fails (flagged via `parsed_ok = false`).
pub fn analyze(source: &str) -> JsFinding {
    let mut finding = JsFinding::default();
    for line in source.lines() {
        if let Some((_, value)) = line.split_once("sourceMappingURL=") {
            let value = value.trim().trim_end_matches(['"', '\'', ';']);
            if !value.is_empty() {
                finding.sourcemap = Some(value.to_string());
            }
        }
    }
    let allocator = Allocator::default();
    let source_type = SourceType::default();
    let parsed = Parser::new(&allocator, source, source_type).parse();
    let mut collector = Collector {
        strings: Vec::new(),
        calls: Vec::new(),
    };
    if parsed.diagnostics.is_empty() {
        collector.visit_program(&parsed.program);
        finding.parsed_ok = true;
    } else {
        finding.parsed_ok = false;
        regex_extract(source, &mut collector.strings);
        // Merge AST strings too: partial parses still visit fine.
        let mut partial = Collector {
            strings: Vec::new(),
            calls: Vec::new(),
        };
        partial.visit_program(&parsed.program);
        collector.strings.extend(partial.strings);
        collector.calls.extend(partial.calls);
    }
    let mut calls: Vec<String> = collector.calls.into_iter().collect();
    calls.sort();
    calls.dedup();
    finding.calls = calls;
    classify(collector.strings, &mut finding);
    finding
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
import axios from 'axios';
const API = "/api/v1/users?role=admin&active=1";
fetch(API).then(r => r.json());
axios.get("/api/v1/orders?limit=20");
const ws = new WebSocket("wss://a.test/socket");
//# sourceMappingURL=app.js.map
"#;

    #[test]
    fn ast_extracts_urls_calls_params() {
        let finding = analyze(SAMPLE);
        assert!(finding.parsed_ok);
        assert!(finding
            .urls
            .contains(&"/api/v1/users?role=admin&active=1".to_string()));
        assert!(finding
            .urls
            .contains(&"/api/v1/orders?limit=20".to_string()));
        assert!(finding.calls.iter().any(|c| c == "fetch"));
        assert!(finding.calls.iter().any(|c| c == "axios.get"));
        assert!(finding.params.contains(&"role".to_string()));
        assert!(finding.params.contains(&"limit".to_string()));
        assert!(finding
            .websockets
            .contains(&"wss://a.test/socket".to_string()));
        assert_eq!(finding.sourcemap, Some("app.js.map".to_string()));
        assert!(finding.secret_kinds.is_empty());
    }

    #[test]
    fn broken_js_falls_back_with_flag() {
        let finding = analyze("const x = { broken(('/api/thing');");
        assert!(!finding.parsed_ok);
        assert!(finding.urls.contains(&"/api/thing".to_string()));
    }

    #[test]
    fn secret_values_never_stored() {
        let source = "const key = \"AKIAIOSFODNN7EXAMPLE\";";
        let finding = analyze(source);
        assert!(finding.secret_kinds.contains(&"aws_key".to_string()));
        let serialized = format!("{finding:?}");
        assert!(!serialized.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
