//! Data-driven technology fingerprinting (rule engine v1).
//!
//! Confidence rubric (tool's own 0.0-1.0 scale, not a probability):
//! a rule's base confidence applies on the first matching signal; each
//! additional independent signal adds 0.1, capped at 0.99. `implies` adds
//! the implied technology at 0.8x confidence with the same evidence;
//! `excludes` drops the excluded technology.

use serde::{Deserialize, Serialize};
use swiftrecon_core::{Confidence, Evidence};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default)]
    pub implies: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub signals: Signals,
}

fn default_confidence() -> f64 {
    0.6
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Signals {
    #[serde(default)]
    pub header_server: Vec<String>,
    #[serde(default)]
    pub header_powered_by: Vec<String>,
    #[serde(default)]
    pub cookies: Vec<String>,
    #[serde(default)]
    pub meta_generator: Vec<String>,
    #[serde(default)]
    pub html: Vec<String>,
}

/// Observed signals from one HTTP service.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub cookie_names: Vec<String>,
    pub meta_generator: Option<String>,
    pub html_excerpt: String,
}

/// One matched technology with evidence.
#[derive(Debug, Clone, Serialize)]
pub struct TechMatch {
    pub name: String,
    pub version: Option<String>,
    pub confidence: f64,
    pub evidence: Vec<Evidence>,
}

pub fn load_rules(text: &str) -> Result<Vec<Rule>, FingerprintError> {
    let file: RuleFile = toml::from_str(text)?;
    Ok(file.rule)
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Match observed signals against rules. Pure function, snapshot-tested.
pub fn fingerprint(rules: &[Rule], observed: &Observed) -> Vec<TechMatch> {
    let mut matches: Vec<TechMatch> = Vec::new();
    for rule in rules {
        let mut evidence: Vec<Evidence> = Vec::new();
        if let Some(server) = &observed.server {
            for needle in &rule.signals.header_server {
                if contains(server, needle) {
                    evidence.push(Evidence::observed("header", "server", server));
                    break;
                }
            }
        }
        if let Some(powered) = &observed.powered_by {
            for needle in &rule.signals.header_powered_by {
                if contains(powered, needle) {
                    evidence.push(Evidence::observed("header", "x-powered-by", powered));
                    break;
                }
            }
        }
        for cookie in &observed.cookie_names {
            if rule
                .signals
                .cookies
                .iter()
                .any(|needle| contains(cookie, needle))
            {
                evidence.push(Evidence::observed("cookie", "name", cookie));
            }
        }
        if let Some(generator) = &observed.meta_generator {
            for needle in &rule.signals.meta_generator {
                if contains(generator, needle) {
                    evidence.push(Evidence::observed("meta", "generator", generator));
                    break;
                }
            }
        }
        for needle in &rule.signals.html {
            if contains(&observed.html_excerpt, needle) {
                evidence.push(Evidence::observed("html", "pattern", needle));
            }
        }
        if evidence.is_empty() {
            continue;
        }
        let extra = evidence.len().saturating_sub(1) as f64;
        let confidence = (rule.confidence + 0.1 * extra).min(0.99);
        matches.push(TechMatch {
            name: rule.name.clone(),
            version: None,
            confidence: Confidence::new(confidence)
                .map(|c| c.value())
                .unwrap_or(rule.confidence),
            evidence,
        });
    }
    // implies: same evidence at 0.8x, capped by the parent's confidence.
    let mut implied = Vec::new();
    for rule in rules {
        if rule.implies.is_empty() {
            continue;
        }
        if let Some(parent) = matches.iter().find(|m| m.name == rule.name) {
            for name in &rule.implies {
                implied.push(TechMatch {
                    name: name.clone(),
                    version: None,
                    confidence: (parent.confidence * 0.8).min(0.99),
                    evidence: parent.evidence.clone(),
                });
            }
        }
    }
    matches.extend(implied);
    // excludes: drop excluded technologies.
    let excluded: Vec<String> = rules
        .iter()
        .filter(|rule| matches.iter().any(|m| m.name == rule.name))
        .flat_map(|rule| rule.excludes.clone())
        .collect();
    matches.retain(|m| !excluded.contains(&m.name));
    matches.sort_by(|a, b| a.name.cmp(&b.name));
    matches
}

#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("rule parse error: {0}")]
    Rules(String),
}

impl From<toml::de::Error> for FingerprintError {
    fn from(err: toml::de::Error) -> Self {
        Self::Rules(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
[[rule]]
name = "nginx"
confidence = 0.7
[rule.signals]
header_server = ["nginx"]

[[rule]]
name = "wordpress"
confidence = 0.8
[rule.signals]
meta_generator = ["wordpress"]
html = ["wp-content"]

[[rule]]
name = "php"
confidence = 0.5
implies = []
excludes = []
[rule.signals]
"#;

    #[test]
    fn header_signal_matches() {
        let rules = load_rules(RULES).unwrap();
        let observed = Observed {
            server: Some("nginx/1.24".to_string()),
            ..Default::default()
        };
        let matches = fingerprint(&rules, &observed);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "nginx");
        assert!(!matches[0].evidence.is_empty());
    }

    #[test]
    fn multi_signal_boosts_confidence() {
        let rules = load_rules(RULES).unwrap();
        let single = fingerprint(
            &rules,
            &Observed {
                meta_generator: Some("WordPress 6.4".to_string()),
                ..Default::default()
            },
        );
        let both = fingerprint(
            &rules,
            &Observed {
                meta_generator: Some("WordPress 6.4".to_string()),
                html_excerpt: "wp-content/themes".to_string(),
                ..Default::default()
            },
        );
        let single_wp = single.iter().find(|m| m.name == "wordpress").unwrap();
        let both_wp = both.iter().find(|m| m.name == "wordpress").unwrap();
        assert!(both_wp.confidence > single_wp.confidence);
        assert!(both_wp.confidence < 1.0);
    }

    #[test]
    fn no_signals_no_match() {
        let rules = load_rules(RULES).unwrap();
        assert!(fingerprint(&rules, &Observed::default()).is_empty());
    }

    #[test]
    fn shipped_rules_load() {
        let text = include_str!("../../../rules/fingerprint.toml");
        let rules = load_rules(text).unwrap();
        assert!(rules.len() >= 8);
    }

    /// Phase 3 exit gate: fixture precision over known stacks plus one
    /// negative (bare page must produce no claim).
    #[test]
    fn lab_tech_precision() {
        let text = include_str!("../../../rules/fingerprint.toml");
        let rules = load_rules(text).unwrap();
        let cases: Vec<(Observed, Option<&str>)> = vec![
            (
                Observed {
                    server: Some("nginx/1.24".to_string()),
                    html_excerpt: include_str!("../../../lab/tech-plain.html").to_string(),
                    ..Default::default()
                },
                Some("nginx"),
            ),
            (
                Observed {
                    server: Some("Apache/2.4".to_string()),
                    html_excerpt: String::new(),
                    ..Default::default()
                },
                Some("apache"),
            ),
            (
                Observed {
                    powered_by: Some("Express".to_string()),
                    html_excerpt: String::new(),
                    ..Default::default()
                },
                Some("express"),
            ),
            (
                Observed {
                    meta_generator: Some("WordPress 6.4".to_string()),
                    html_excerpt: include_str!("../../../lab/tech-wordpress.html").to_string(),
                    ..Default::default()
                },
                Some("wordpress"),
            ),
            (
                Observed {
                    html_excerpt: include_str!("../../../lab/tech-react.html").to_string(),
                    ..Default::default()
                },
                Some("react"),
            ),
            (
                Observed {
                    server: Some("UnknownServer/0.0".to_string()),
                    html_excerpt: include_str!("../../../lab/tech-plain.html").to_string(),
                    ..Default::default()
                },
                None,
            ),
        ];
        let mut true_positives = 0;
        let mut claimed = 0;
        for (observed, expected) in &cases {
            let matches = fingerprint(&rules, observed);
            match expected {
                Some(name) => {
                    assert!(
                        matches.iter().any(|m| &m.name == name),
                        "expected {name} in {:?}",
                        matches.iter().map(|m| &m.name).collect::<Vec<_>>()
                    );
                    true_positives += 1;
                    claimed += matches.len();
                }
                None => {
                    assert!(
                        matches.is_empty(),
                        "bare page must not claim tech: {matches:?}"
                    );
                }
            }
        }
        let precision = true_positives as f64 / claimed.max(1) as f64;
        eprintln!("lab tech: precision={precision:.4}");
        assert!(
            precision >= 0.95,
            "tech precision {precision:.3} below 0.95"
        );
    }
}
