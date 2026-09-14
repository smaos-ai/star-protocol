//! DORA Threshold Assessment Engine (Strict Human-in-the-Loop Classification).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdMetrics {
    pub affected_clients: u64,
    pub affected_tx: u64,
    pub duration_min: u64,
    pub geographic_spread: String,
    pub is_critical: bool,
    pub data_integrity_impact: bool,
    pub economic_impact_eur: f64,
    pub unknown_actions_count: u64, // SMAOS core differentiator
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DoraClassification {
    NotMajor,
    MajorCandidate,
    ClassificationRequired,
    ClassifiedMajorByHuman,
    ClassifiedNonMajorByHuman,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdEvaluation {
    pub classification: DoraClassification,
    pub human_approver_required: bool,
    pub triggers_fired: Vec<String>,
    pub rationale: String,
}

pub struct DoraThresholdEngine;

impl DoraThresholdEngine {
    /// Evaluates metrics against DORA Article 18 threshold criteria.
    /// Note: The engine NEVER autonomously makes a legally binding Major classification.
    /// It flags `MajorCandidate` or `ClassificationRequired` requiring signed human sign-off.
    pub fn evaluate(metrics: &ThresholdMetrics) -> ThresholdEvaluation {
        let mut triggers = Vec::new();

        if metrics.economic_impact_eur >= 100_000.0 {
            triggers.push(format!(
                "Economic impact €{:.2} exceeds €100k material loss threshold",
                metrics.economic_impact_eur
            ));
        }

        if metrics.duration_min >= 120 {
            triggers.push(format!(
                "Outage duration {} min exceeds 2-hour materiality criterion",
                metrics.duration_min
            ));
        }

        if metrics.affected_clients >= 10_000 {
            triggers.push(format!(
                "Affected clients count {} exceeds 10k threshold",
                metrics.affected_clients
            ));
        }

        if metrics.is_critical && metrics.data_integrity_impact {
            triggers
                .push("Critical function affected with unconfirmed data integrity impact".into());
        }

        if metrics.unknown_actions_count > 0 {
            triggers.push(format!(
                "SMAOS UNKNOWN state invariant: {} actions have unconfirmed external effects",
                metrics.unknown_actions_count
            ));
        }

        if triggers.is_empty() {
            ThresholdEvaluation {
                classification: DoraClassification::NotMajor,
                human_approver_required: false,
                triggers_fired: Vec::new(),
                rationale: "No statutory materiality thresholds breached".into(),
            }
        } else if triggers.len() >= 2 || metrics.unknown_actions_count > 0 {
            ThresholdEvaluation {
                classification: DoraClassification::MajorCandidate,
                human_approver_required: true,
                triggers_fired: triggers,
                rationale: "Statutory thresholds breached; immediate human assessment required under DORA Article 18".into(),
            }
        } else {
            ThresholdEvaluation {
                classification: DoraClassification::ClassificationRequired,
                human_approver_required: true,
                triggers_fired: triggers,
                rationale: "Single indicator triggered; human compliance sign-off required".into(),
            }
        }
    }
}
