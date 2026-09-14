//! Cost-of-Uncertainty Accounting Engine for DORA Regulatory Exposure.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncertaintyExposure {
    pub action_id: String,
    pub amount_eur: f64,
    pub risk_tier: String,
    pub state: String,
    pub unconfirmed_since_iso: String,
    pub duration_seconds: u64,
    pub is_escalation_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureReport {
    pub total_uncertain_actions: usize,
    pub gross_cost_of_uncertainty_eur: f64,
    pub max_single_action_exposure_eur: f64,
    pub high_risk_actions_count: usize,
    pub escalated_actions_count: usize,
    pub threshold_breached: bool,
}

pub struct ExposureEngine;

impl ExposureEngine {
    pub const DEFAULT_ESCALATION_TIMEOUT_SECONDS: u64 = 900; // 15 minutes

    /// Creates an uncertainty exposure entry from an unconfirmed action.
    pub fn new_exposure(
        action_id: &str,
        amount_eur: f64,
        risk_tier: &str,
        state: &str,
        unconfirmed_since_iso: &str,
        duration_seconds: u64,
    ) -> UncertaintyExposure {
        UncertaintyExposure {
            action_id: action_id.to_string(),
            amount_eur,
            risk_tier: risk_tier.to_string(),
            state: state.to_string(),
            unconfirmed_since_iso: unconfirmed_since_iso.to_string(),
            duration_seconds,
            is_escalation_required: duration_seconds > Self::DEFAULT_ESCALATION_TIMEOUT_SECONDS,
        }
    }

    /// Evaluates cumulative financial uncertainty and DORA threshold breach probability.
    pub fn evaluate_exposure(
        actions: &[UncertaintyExposure],
        regulatory_threshold_eur: f64,
    ) -> ExposureReport {
        let mut total_cost = 0.0;
        let mut max_single = 0.0;
        let mut high_risk_count = 0;
        let mut escalated_count = 0;

        for a in actions {
            if a.state == "UNKNOWN" || a.state == "UNCONFIRMED" || a.state == "TIMED_OUT" {
                total_cost += a.amount_eur;
                if a.amount_eur > max_single {
                    max_single = a.amount_eur;
                }
                if a.risk_tier == "T3_CRITICAL" || a.risk_tier == "T2_HIGH" {
                    high_risk_count += 1;
                }
                if a.is_escalation_required {
                    escalated_count += 1;
                }
            }
        }

        let threshold_breached = total_cost >= regulatory_threshold_eur || escalated_count > 0;

        ExposureReport {
            total_uncertain_actions: actions.len(),
            gross_cost_of_uncertainty_eur: total_cost,
            max_single_action_exposure_eur: max_single,
            high_risk_actions_count: high_risk_count,
            escalated_actions_count: escalated_count,
            threshold_breached,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exposure_calculation_and_escalation() {
        let e1 = ExposureEngine::new_exposure(
            "ACT-001",
            1_850_000.0,
            "T3_CRITICAL",
            "UNKNOWN",
            "2026-09-14T08:00:00Z",
            1200, // > 900s -> escalated
        );
        let e2 = ExposureEngine::new_exposure(
            "ACT-002",
            500_000.0,
            "T2_HIGH",
            "SETTLED", // Settled actions not counted in uncertainty
            "2026-09-14T08:10:00Z",
            300,
        );

        assert!(e1.is_escalation_required);
        assert!(!e2.is_escalation_required);

        let report = ExposureEngine::evaluate_exposure(&[e1, e2], 1_000_000.0);
        assert_eq!(report.gross_cost_of_uncertainty_eur, 1_850_000.0);
        assert_eq!(report.escalated_actions_count, 1);
        assert!(report.threshold_breached);
    }
}
