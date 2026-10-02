//! Native Rust Integration Test Suite for smaos-dora-kit
//! Verifies core verification invariants, cryptographic integrity, and all 6 negative vectors.

use chrono::Utc;
use smaos_dora_kit::{
    DoraClockEngine, DoraJournal, DoraScenarioGenerator, DoraThresholdEngine,
    DoraTimelineReconstructor, IncidentClockState, JournalEventKind,
    ThresholdMetrics, DoraClassification,
};
use std::collections::HashSet;

#[test]
fn test_native_ghost_incident_timeline_reconstruction() {
    let bundle = DoraScenarioGenerator::generate_canonical_ghost_incident()
        .expect("canonical ghost incident generation failed");
    assert_eq!(bundle.total_events, 10);
    assert_eq!(bundle.events.len(), 10);

    // Verify chronological order and strictly increasing sequence
    for i in 0..bundle.events.len() {
        assert_eq!(bundle.events[i].sequence, (i + 1) as u64);
    }

    // Full T0..T9 timeline reconstruction
    let timeline = DoraTimelineReconstructor::reconstruct_timeline(
        "ACT-SWIFT-9901",
        &bundle.events,
    );
    assert_eq!(timeline.phases.len(), 10);
    assert!(timeline.unknown_declared_at.is_some());
    assert!(timeline.total_uncertainty_window_seconds.is_some());
}

#[test]
fn test_native_jcs_hash_chain_tamper_rejection() {
    let mut journal = DoraJournal::new_in_memory();
    assert_eq!(journal.latest_hash(), DoraJournal::GENESIS_HASH);

    let e1 = journal
        .append_event(
            "ACT-001",
            JournalEventKind::Proposed {
                action_id: "ACT-001".into(),
                risk_tier: "T3".into(),
            },
            "2026-09-14T08:00:00Z",
            1000,
            Some(1726300800),
            5,
        )
        .expect("append event 1");

    assert_eq!(e1.sequence, 1);
    assert_eq!(e1.prev_hash, DoraJournal::GENESIS_HASH);

    let e2 = journal
        .append_event(
            "ACT-001",
            JournalEventKind::Authorized {
                permit_id: "PERMIT-001".into(),
                scope: "SWIFT_WIRE".into(),
            },
            "2026-09-14T08:00:01Z",
            2000,
            Some(1726300801),
            5,
        )
        .expect("append event 2");

    assert_eq!(e2.sequence, 2);
    assert_eq!(e2.prev_hash, e1.event_hash);

    // Verify chain validates intact
    assert!(journal.verify_full_chain().is_ok());

    // Adversarial tampering: mutate sequence or hash in event 1
    let mut tampered_journal = journal.clone();
    tampered_journal.events[0].event_hash = "corrupted_hash_000000000000000000000000".into();
    assert!(tampered_journal.verify_full_chain().is_err());
}

#[test]
fn test_native_all_6_negative_fault_vectors() {
    // Vector 1: Missing Reconciliation Record -> Fail Closed UNRESOLVED
    assert!(
        DoraScenarioGenerator::vector_not_found().expect("vector 1 check failed"),
        "Vector 1: missing reconciliation must fail closed"
    );

    // Vector 2: Conflicting State Records -> Conflict Detected
    assert!(
        DoraScenarioGenerator::vector_conflict().expect("vector 2 check failed"),
        "Vector 2: conflicting records must trigger conflict disposition"
    );

    // Vector 3: Pre-Dispatch Denied vs Post-Dispatch Unknown Halt
    assert_eq!(
        DoraScenarioGenerator::vector_pre_vs_post_loss(true),
        "PRE_DISPATCH_DENIED_NO_EFFECT"
    );
    assert_eq!(
        DoraScenarioGenerator::vector_pre_vs_post_loss(false),
        "POST_DISPATCH_UNKNOWN_HALT"
    );

    // Vector 4: Manipulated Merkle / Hash Chain Fails Verification
    assert!(
        DoraScenarioGenerator::vector_manipulated_chain_fails(),
        "Vector 4: modified chain must fail integrity check"
    );

    // Vector 5: Duplicate Reconciliation Nonce Replay Rejected
    let mut seen_nonces = HashSet::new();
    assert!(
        !DoraScenarioGenerator::vector_duplicate_replay_detected(&mut seen_nonces, "nonce-auth-001"),
        "First nonce submission must not be flagged as replay"
    );
    assert!(
        DoraScenarioGenerator::vector_duplicate_replay_detected(&mut seen_nonces, "nonce-auth-001"),
        "Duplicate nonce replay must be detected and rejected"
    );

    // Vector 6: Single-Operator Recovery Fails Two-Person Rule
    assert!(
        DoraScenarioGenerator::vector_single_operator_rejected(),
        "Vector 6: single-operator override must be rejected under dual-control rule"
    );
}

#[test]
fn test_native_dora_regulatory_deadlines_and_clocks() {
    let now = Utc::now();
    let awareness_time = now.to_rfc3339();

    // Awareness recorded -> initial 24h clock running
    let status_init = DoraClockEngine::evaluate_clocks(Some(&awareness_time), None, None, None, now);
    assert_eq!(
        status_init.clock_state,
        IncidentClockState::AwarenessRecordedClassificationPending
    );
    assert!(status_init.is_classification_pending);

    // Major Incident Classification -> triggers Article 19 statutory reporting deadlines (4h, 72h, 30d)
    let class_time = (now + chrono::Duration::hours(1)).to_rfc3339();
    let status_major = DoraClockEngine::evaluate_clocks(
        Some(&awareness_time),
        Some(&class_time),
        Some("Major"),
        Some("LEAD_OPERATOR_01"),
        now,
    );
    assert_eq!(
        status_major.clock_state,
        IncidentClockState::MajorClassificationRecorded
    );
    assert!(!status_major.is_classification_pending);
    assert_eq!(status_major.deadlines.len(), 4);
}

#[test]
fn test_native_dora_threshold_evaluation_major_classification() {
    let metrics = ThresholdMetrics {
        affected_clients: 25_000,
        affected_tx: 1_200,
        duration_min: 180,
        geographic_spread: "EU_CROSS_BORDER".into(),
        is_critical: true,
        data_integrity_impact: true,
        economic_impact_eur: 2_500_000.0,
        unknown_actions_count: 1,
    };

    let evaluation = DoraThresholdEngine::evaluate(&metrics);
    assert_eq!(evaluation.classification, DoraClassification::MajorCandidate);
    assert!(evaluation.human_approver_required);
    assert!(!evaluation.triggers_fired.is_empty());
}
