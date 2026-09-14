//! SMAOS DORA AI Incident Closure Engine — Tabletop Kit (smaos-dora-kit).

pub mod clock;
pub mod config_lineage;
pub mod exposure;
pub mod journal;
pub mod obligations;
pub mod protocol_drift;
pub mod review;
pub mod scenario;
pub mod threshold;
pub mod timeline;

pub use clock::{DoraClockEngine, DoraCountdownStatus, DoraDeadline, IncidentClockState};
pub use config_lineage::{ConfigLineageGraph, ConfigMutation};
pub use exposure::{ExposureEngine, ExposureReport, UncertaintyExposure};
pub use journal::{DoraJournal, JournalError, JournalEvent, JournalEventKind};
pub use obligations::{
    Article8Status, AuthenticatedReconciliationEvent, CalculatedDeadline, CalendarError,
    DirectLossPartition, EntityType, MemberStateCalendar, ObligationType, ReconciliationOutcome,
    StatutoryDeadlineEngine,
};
pub use protocol_drift::{DriftReport, ProtocolDriftDetector};
pub use review::{
    BusinessTransactionMetrics, ConservationScorecard, CounterfactualReplay, CriteriaMatrix,
    EvidenceManifest, KpiBaseline, RejectedRowDetail, ReviewError, ReviewProcessor,
    ServiceNowCaseExport, SourceContract, UnknownExposureInventory, UnknownExposureItem,
};
pub use scenario::{DoraScenarioGenerator, GhostScenarioBundle};
pub use threshold::{
    DoraClassification, DoraThresholdEngine, ThresholdEvaluation, ThresholdMetrics,
};
pub use timeline::{
    DoraTimelineReconstructor, EvidenceConfidence, EvidenceStatus, ReconstructedTimeline,
    TimelinePhase,
};

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashSet;

    #[test]
    fn test_happy_path_ghost_incident() {
        let bundle = DoraScenarioGenerator::generate_canonical_ghost_incident().unwrap();
        assert_eq!(bundle.total_events, 10);
        assert_eq!(bundle.events.len(), 10);

        // Verify sequence order
        for event in &bundle.events {
            assert!(event.sequence > 0);
        }

        // Reconstruct T0-T9 timeline
        let timeline =
            DoraTimelineReconstructor::reconstruct_timeline("ACT-SWIFT-9901", &bundle.events);
        assert_eq!(timeline.phases.len(), 10);
        assert!(timeline.unknown_declared_at.is_some());
        assert!(timeline.total_uncertainty_window_seconds.is_some());
    }

    #[test]
    fn test_dora_regulatory_countdown() {
        let now = Utc::now();
        let awareness_time = now.to_rfc3339();

        // 1. Awareness recorded, classification pending
        let status1 =
            DoraClockEngine::evaluate_clocks(Some(&awareness_time), None, None, None, now);
        assert_eq!(
            status1.clock_state,
            IncidentClockState::AwarenessRecordedClassificationPending
        );
        assert!(status1.is_classification_pending);
        assert_eq!(status1.deadlines.len(), 1); // 24h awareness window

        // 2. Human classified as Major -> triggers 4h, 72h, 30d
        let class_time = (now + chrono::Duration::hours(1)).to_rfc3339();
        let status2 = DoraClockEngine::evaluate_clocks(
            Some(&awareness_time),
            Some(&class_time),
            Some("Major"),
            Some("CRO_SLOT9C"),
            now,
        );
        assert_eq!(
            status2.clock_state,
            IncidentClockState::MajorClassificationRecorded
        );
        assert!(!status2.is_classification_pending);
        assert_eq!(status2.deadlines.len(), 4);
    }

    #[test]
    fn test_dora_threshold_evaluation() {
        let metrics = ThresholdMetrics {
            affected_clients: 15_000,
            affected_tx: 500,
            duration_min: 150,
            geographic_spread: "EU_CROSS_BORDER".into(),
            is_critical: true,
            data_integrity_impact: true,
            economic_impact_eur: 1_850_000.0,
            unknown_actions_count: 1,
        };

        let eval = DoraThresholdEngine::evaluate(&metrics);
        assert_eq!(eval.classification, DoraClassification::MajorCandidate);
        assert!(eval.human_approver_required);
        assert!(!eval.triggers_fired.is_empty());
    }

    #[test]
    fn test_all_6_negative_vectors() {
        // Vector 1: NotFound unresolved
        assert!(DoraScenarioGenerator::vector_not_found().unwrap());

        // Vector 2: Conflict detected
        assert!(DoraScenarioGenerator::vector_conflict().unwrap());

        // Vector 3: Pre vs Post loss
        assert_eq!(
            DoraScenarioGenerator::vector_pre_vs_post_loss(true),
            "PRE_DISPATCH_DENIED_NO_EFFECT"
        );
        assert_eq!(
            DoraScenarioGenerator::vector_pre_vs_post_loss(false),
            "POST_DISPATCH_UNKNOWN_HALT"
        );

        // Vector 4: Tampered payload caught
        assert!(DoraScenarioGenerator::vector_manipulated_chain_fails());

        // Vector 5: Duplicate reconciliation replay
        let mut seen = HashSet::new();
        assert!(!DoraScenarioGenerator::vector_duplicate_replay_detected(
            &mut seen, "nonce1"
        ));
        assert!(DoraScenarioGenerator::vector_duplicate_replay_detected(
            &mut seen, "nonce1"
        ));

        // Vector 6: Single-operator recovery rejected fail-closed
        assert!(DoraScenarioGenerator::vector_single_operator_rejected());
    }
}
