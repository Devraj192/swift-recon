//! Core fact, evidence, and confidence types shared by all SwiftRecon crates.
//!
//! Every discovered fact carries its sources, raw evidence, and a confidence
//! score on the tool's own 0.0-1.0 scale (not a probability).

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Tool-owned confidence score in 0.0-1.0. Not a probability.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Confidence(pub f64);

impl Confidence {
    pub fn new(value: f64) -> Result<Self, CoreError> {
        if !(0.0..=1.0).contains(&value) {
            return Err(CoreError::InvalidConfidence(value));
        }
        Ok(Self(value))
    }

    /// Combine two independent signals without exceeding 1.0 (noisy-OR style, capped).
    pub fn combine_noisy_or(a: Self, b: Self) -> Self {
        let combined = 1.0 - (1.0 - a.0) * (1.0 - b.0);
        Self(combined.min(0.99))
    }

    pub fn value(self) -> f64 {
        self.0
    }
}

/// Where a piece of evidence was directly seen vs concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Observed,
    Inferred,
}

/// One raw piece of evidence behind a fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: ObservationKind,
    pub evidence_type: String,
    pub key: String,
    pub value: String,
}

impl Evidence {
    pub fn observed(evidence_type: &str, key: &str, value: &str) -> Self {
        Self {
            kind: ObservationKind::Observed,
            evidence_type: evidence_type.to_string(),
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    pub fn inferred(evidence_type: &str, key: &str, value: &str) -> Self {
        Self {
            kind: ObservationKind::Inferred,
            evidence_type: evidence_type.to_string(),
            key: key.to_string(),
            value: value.to_string(),
        }
    }
}

/// A single correlated, evidence-backed fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fact {
    pub id: String,
    pub scan_id: String,
    pub kind: String,
    pub value: String,
    pub sources: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub confidence: Confidence,
    pub first_seen: i64,
    pub last_seen: i64,
}

impl Fact {
    pub fn new(
        scan_id: &str,
        kind: &str,
        value: &str,
        sources: Vec<String>,
        evidence: Vec<Evidence>,
        confidence: Confidence,
    ) -> Self {
        let now = now_unix();
        Self {
            id: format!("{}:{}:{}", scan_id, kind, value),
            scan_id: scan_id.to_string(),
            kind: kind.to_string(),
            value: value.to_string(),
            sources,
            evidence,
            confidence,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Merge a duplicate: union sources and evidence, keep max confidence.
    pub fn merge(&mut self, other: &Fact) {
        for source in &other.sources {
            if !self.sources.contains(source) {
                self.sources.push(source.clone());
            }
        }
        for item in &other.evidence {
            if !self.evidence.contains(item) {
                self.evidence.push(item.clone());
            }
        }
        if other.confidence.0 > self.confidence.0 {
            self.confidence = other.confidence;
        }
        self.last_seen = self.last_seen.max(other.last_seen);
    }
}

/// Typed events passed over bounded channels between pipeline stages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    FactDiscovered {
        fact: Fact,
    },
    StageFinished {
        stage: String,
        scan_id: String,
    },
    StageFailed {
        stage: String,
        scan_id: String,
        error: String,
    },
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("confidence {0} out of range 0.0-1.0")]
    InvalidConfidence(f64),
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_rejects_out_of_range() {
        assert!(Confidence::new(1.5).is_err());
        assert!(Confidence::new(-0.1).is_err());
        assert!(Confidence::new(0.9).is_ok());
    }

    #[test]
    fn merge_unions_sources_and_evidence() {
        let mut a = Fact::new(
            "scan1",
            "subdomain",
            "a.example.com",
            vec!["crtsh".to_string()],
            vec![Evidence::observed("dns", "a", "1.1.1.1")],
            Confidence(0.7),
        );
        let b = Fact::new(
            "scan1",
            "subdomain",
            "a.example.com",
            vec!["otx".to_string()],
            vec![Evidence::observed("dns", "a", "1.1.1.1")],
            Confidence(0.8),
        );
        a.merge(&b);
        assert_eq!(a.sources.len(), 2);
        assert_eq!(a.evidence.len(), 1);
        assert_eq!(a.confidence.value(), 0.8);
    }

    #[test]
    fn noisy_or_caps_below_one() {
        let c = Confidence::combine_noisy_or(Confidence(0.9), Confidence(0.9));
        assert!(c.value() < 1.0);
        assert!(c.value() > 0.9);
    }
}
