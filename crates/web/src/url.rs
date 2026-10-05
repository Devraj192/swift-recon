//! URL canonicalization, endpoint templating, and parameter extraction.
//!
//! Normalization happens before dedup and MUST be idempotent
//! (`canonicalize(canonicalize(u)) == canonicalize(u)`, proptested).

use std::collections::{BTreeMap, HashSet};

/// Tracking params stripped before dedup (configurable list lives here, v1).
const TRACKING_PARAMS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
];

/// Canonicalize a URL: lowercase scheme/host, drop default ports and
/// fragments, collapse `//`, consistent trailing-slash policy (root keeps
/// `/`, others drop it), sorted query params, tracking params stripped.
/// Returns `None` for unparseable input.
pub fn canonicalize(raw: &str) -> Option<String> {
    let mut url = url::Url::parse(raw.trim()).ok()?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return None;
    }
    url.set_scheme(url.scheme().to_lowercase().as_str()).ok()?;
    if let Some(host) = url.host_str() {
        url.set_host(Some(&host.to_lowercase())).ok()?;
    }
    // Drop default ports.
    if (url.scheme() == "http" && url.port() == Some(80))
        || (url.scheme() == "https" && url.port() == Some(443))
    {
        url.set_port(None).ok()?;
    }
    url.set_fragment(None);
    // Collapse duplicate slashes in the path.
    let mut path = String::with_capacity(url.path().len());
    let mut last_slash = false;
    for ch in url.path().chars() {
        if ch == '/' {
            if last_slash {
                continue;
            }
            last_slash = true;
        } else {
            last_slash = false;
        }
        path.push(ch);
    }
    // Consistent trailing slash: root keeps `/`, others drop it.
    if path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    if path.is_empty() {
        path.push('/');
    }
    url.set_path(&path);
    // Sorted, de-tracking query params.
    let kept: BTreeMap<String, String> = url
        .query_pairs()
        .filter(|(k, _)| !TRACKING_PARAMS.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.set_query(None);
    if !kept.is_empty() {
        let query = kept
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        url.set_query(Some(&query));
    }
    Some(url.to_string())
}

fn percent_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Resolve a possibly-relative URL against a base (page or JS file URL).
/// Absolute inputs pass through unchanged. Returns `None` when unparseable.
pub fn resolve_against(base: &str, raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(absolute) = url::Url::parse(raw) {
        if absolute.scheme() == "http" || absolute.scheme() == "https" {
            return Some(absolute.to_string());
        }
        return None;
    }
    url::Url::parse(base)
        .and_then(|b| b.join(raw))
        .ok()
        .and_then(|joined| {
            if joined.scheme() == "http" || joined.scheme() == "https" {
                Some(joined.to_string())
            } else {
                None
            }
        })
}

/// Group ID-like path segments: all-digit, UUID-shaped, or long hex/base64
/// tokens become `{id}`. Returns the template path (or full template URL
/// when the input parses).
pub fn template_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if is_id_like(segment) {
                "{id}".to_string()
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_id_like(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    // UUID-shaped.
    if segment.len() == 36 && segment.chars().filter(|c| *c == '-').count() == 4 {
        return true;
    }
    // Long opaque tokens (hex/base64url, 16+ chars, mixed).
    if segment.len() >= 16
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && segment.chars().any(|c| c.is_ascii_digit())
        && segment.chars().any(|c| c.is_ascii_alphabetic())
    {
        return true;
    }
    false
}

/// One extracted parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Parameter {
    pub name: String,
    pub location: ParamLocation,
    pub method: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamLocation {
    Query,
    Body,
    Path,
    Header,
}

/// Query params from a canonical URL.
pub fn query_params(canonical_url: &str, source: &str) -> Vec<Parameter> {
    let url = match url::Url::parse(canonical_url) {
        Ok(url) => url,
        Err(_) => return Vec::new(),
    };
    let mut seen = HashSet::new();
    url.query_pairs()
        .filter(|(k, _)| seen.insert(k.to_string()))
        .map(|(k, _)| Parameter {
            name: k.into_owned(),
            location: ParamLocation::Query,
            method: "GET".to_string(),
            sources: vec![source.to_string()],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn canonical_basics() {
        assert_eq!(
            canonicalize("HTTP://Example.COM:80/a//b/?b=2&a=1#frag"),
            Some("http://example.com/a/b?a=1&b=2".to_string())
        );
        assert_eq!(
            canonicalize("https://example.com:443/"),
            Some("https://example.com/".to_string())
        );
        assert_eq!(
            canonicalize("https://example.com/a/?utm_source=x&b=1"),
            Some("https://example.com/a?b=1".to_string())
        );
        assert!(canonicalize("ftp://example.com/").is_none());
        assert!(canonicalize("not a url").is_none());
    }

    #[test]
    fn templating() {
        assert_eq!(template_path("/users/123/profile"), "/users/{id}/profile");
        assert_eq!(
            template_path("/o/550e8400-e29b-41d4-a716-446655440000/x"),
            "/o/{id}/x"
        );
        assert_eq!(template_path("/users/new"), "/users/new");
    }

    proptest! {
        #[test]
        fn canonical_is_idempotent(raw in "https?://[a-z0-9.-]{1,30}(/[a-zA-Z0-9._~%!$&'()*+,;=:@/-]{0,60})?(\\?[a-z0-9&=%.-]{0,40})?") {
            if let Some(once) = canonicalize(&raw) {
                prop_assert_eq!(canonicalize(&once), Some(once));
            }
        }

        #[test]
        fn template_collapses_ids(path in "/[a-z]{1,8}/[0-9]{1,10}") {
            let templated = template_path(&path);
            let marker = ["{", "id", "}"].concat();
            prop_assert!(templated.ends_with(&marker));
        }
    }
}
