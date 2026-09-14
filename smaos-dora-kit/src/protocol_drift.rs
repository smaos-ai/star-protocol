//! Protocol Drift and Non-Human Vocabulary / Token-Distribution Anomaly Detector.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub is_anomaly: bool,
    pub confidence: f64,
    pub affected_agents: Vec<String>,
    pub anomaly_reasons: Vec<String>,
    pub vocabulary_divergence: f64,
    pub entropy_delta: f64,
}

pub struct ProtocolDriftDetector {
    pub baseline_vocabulary: HashSet<String>,
    pub max_allowed_oov_rate: f64,
    pub max_entropy_divergence: f64,
}

impl Default for ProtocolDriftDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDriftDetector {
    pub fn new() -> Self {
        let mut baseline = HashSet::new();
        // Standard financial / API tokens baseline
        for word in &[
            "action",
            "propose",
            "authorize",
            "dispatch",
            "telemetry",
            "reconcile",
            "timeout",
            "settle",
            "transfer",
            "amount",
            "eur",
            "swift",
            "gateway",
            "account",
            "balance",
            "status",
            "permit",
            "cro",
            "ciso",
            "confirm",
            "reject",
            "conflict",
            "unknown",
            "safe",
            "mode",
            "halt",
            "recovery",
            "audit",
            "compliance",
            "dora",
            "article",
            "incident",
            "report",
            "ledger",
        ] {
            baseline.insert(word.to_string());
        }

        Self {
            baseline_vocabulary: baseline,
            max_allowed_oov_rate: 0.25, // 25% out-of-vocabulary threshold
            max_entropy_divergence: 1.5,
        }
    }

    /// Calculates Shannon entropy of a tokenized message slice.
    pub fn calculate_entropy(tokens: &[String]) -> f64 {
        if tokens.is_empty() {
            return 0.0;
        }
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for t in tokens {
            *counts.entry(t.as_str()).or_insert(0) += 1;
        }

        let total = tokens.len() as f64;
        let mut entropy = 0.0;
        for &c in counts.values() {
            let p = (c as f64) / total;
            entropy -= p * p.log2();
        }
        entropy
    }

    /// Tokenizes raw text by splitting on non-alphanumeric characters.
    pub fn tokenize(text: &str) -> Vec<String> {
        text.to_lowercase()
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    /// Analyzes inter-agent communication messages to detect non-human protocol drift or synthetic jargon.
    pub fn analyze_agent_dialogue(&self, agent_id: &str, messages: &[String]) -> DriftReport {
        let mut all_tokens = Vec::new();
        for m in messages {
            all_tokens.extend(Self::tokenize(m));
        }

        if all_tokens.is_empty() {
            return DriftReport {
                is_anomaly: false,
                confidence: 1.0,
                affected_agents: vec![agent_id.to_string()],
                anomaly_reasons: vec![],
                vocabulary_divergence: 0.0,
                entropy_delta: 0.0,
            };
        }

        let mut oov_count = 0;
        for t in &all_tokens {
            if !self.baseline_vocabulary.contains(t) {
                oov_count += 1;
            }
        }

        let oov_rate = (oov_count as f64) / (all_tokens.len() as f64);
        let entropy = Self::calculate_entropy(&all_tokens);
        let baseline_entropy = 3.2; // Typical baseline conversational entropy
        let entropy_delta = (entropy - baseline_entropy).abs();

        let mut anomaly_reasons = Vec::new();
        let mut is_anomaly = false;

        if oov_rate > self.max_allowed_oov_rate {
            is_anomaly = true;
            anomaly_reasons.push(format!(
                "Non-human emergent vocabulary detected: Out-Of-Vocabulary rate {:.2}% > threshold {:.2}%",
                oov_rate * 100.0,
                self.max_allowed_oov_rate * 100.0
            ));
        }

        if entropy_delta > self.max_entropy_divergence {
            is_anomaly = true;
            anomaly_reasons.push(format!(
                "Abnormal Shannon entropy shift: delta {:.2} > threshold {:.2}",
                entropy_delta, self.max_entropy_divergence
            ));
        }

        let confidence = if is_anomaly {
            (0.5 + (oov_rate * 0.5)).min(0.99)
        } else {
            0.95
        };

        DriftReport {
            is_anomaly,
            confidence,
            affected_agents: vec![agent_id.to_string()],
            anomaly_reasons,
            vocabulary_divergence: oov_rate,
            entropy_delta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_agent_dialogue_passes() {
        let detector = ProtocolDriftDetector::new();
        let msgs = vec![
            "Propose transfer amount 1850000 EUR via SWIFT gateway".into(),
            "CRO permit authorized status confirm".into(),
        ];
        let report = detector.analyze_agent_dialogue("AGENT-PAYMENT-01", &msgs);
        assert!(!report.is_anomaly);
        assert!(report.anomaly_reasons.is_empty());
    }

    #[test]
    fn test_protocol_drift_anomaly_detected() {
        let detector = ProtocolDriftDetector::new();
        let corrupted_msgs = vec![
            "xq99_001_synth_payload_chunk_zxa".into(),
            "flx_909_b12_qqq_zzz_018284_mismatch".into(),
            "non_human_shorthand_cryptic_glyph_loop".into(),
        ];
        let report = detector.analyze_agent_dialogue("AGENT-ROGUE-02", &corrupted_msgs);
        assert!(report.is_anomaly);
        assert!(!report.anomaly_reasons.is_empty());
        assert_eq!(report.affected_agents, vec!["AGENT-ROGUE-02"]);
    }
}
