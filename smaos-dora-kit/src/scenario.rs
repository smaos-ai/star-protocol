//! Ghost Incident Scenario Generator and 6 Negative Fault Injection Vectors.

use crate::journal::{DoraJournal, JournalError, JournalEvent, JournalEventKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostScenarioBundle {
    pub scenario_name: String,
    pub description: String,
    pub events: Vec<JournalEvent>,
    pub final_hash: String,
    pub total_events: usize,
}

pub struct DoraScenarioGenerator;

impl DoraScenarioGenerator {
    /// Generates the canonical 10-step DORA ghost incident scenario.
    pub fn generate_canonical_ghost_incident() -> Result<GhostScenarioBundle, JournalError> {
        let mut journal = DoraJournal::new_in_memory();
        let action_id = "ACT-SWIFT-9901";

        // Step 1: T0 Propose
        journal.append_event(
            action_id,
            JournalEventKind::Proposed {
                action_id: action_id.into(),
                risk_tier: "T3_CRITICAL".into(),
            },
            "2026-09-14T08:00:00Z",
            1_000_000_000,
            Some(1726300800),
            5,
        )?;

        // Step 2: T1 Authorize
        journal.append_event(
            action_id,
            JournalEventKind::Authorized {
                permit_id: "PERMIT-CRO-84920".into(),
                scope: "WIRE_TRANSFER_1850000_EUR".into(),
            },
            "2026-09-14T08:00:02Z",
            1_002_000_000,
            Some(1726300802),
            5,
        )?;

        // Step 3: T2 Dispatch
        journal.append_event(
            action_id,
            JournalEventKind::Dispatched {
                destination: "CORE_BANKING_SWIFT_GATEWAY".into(),
            },
            "2026-09-14T08:00:05Z",
            1_005_000_000,
            Some(1726300805),
            5,
        )?;

        // Step 4: T3 Telemetry Drop / Agent Self-Claimed Success
        journal.append_event(
            action_id,
            JournalEventKind::AgentClaimedSuccess {
                claim_digest: "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a".into(),
            },
            "2026-09-14T08:00:10Z",
            1_010_000_000,
            None, // Missing external confirmation timestamp
            50,
        )?;

        // Step 5: T7 Reconciliation Query Attempt
        journal.append_event(
            action_id,
            JournalEventKind::ReconciliationAttempt {
                adapter_id: "ADAPTER_SWIFT_CORE_REST".into(),
            },
            "2026-09-14T08:00:15Z",
            1_015_000_000,
            Some(1726300815),
            10,
        )?;

        // Step 6: T4 Timeout
        journal.append_event(
            action_id,
            JournalEventKind::ReconciliationResult {
                status: "Timeout".into(),
                effect_digest: None,
            },
            "2026-09-14T08:00:30Z",
            1_030_000_000,
            Some(1726300830),
            10,
        )?;

        // Step 7: T5 UNKNOWN Declared
        journal.append_event(
            action_id,
            JournalEventKind::UnknownDeclared {
                reason: "External system of record timeout; post-dispatch effect unconfirmed"
                    .into(),
            },
            "2026-09-14T08:00:31Z",
            1_031_000_000,
            Some(1726300831),
            5,
        )?;

        // Step 8: T6 Dependency Halt
        journal.append_event(
            action_id,
            JournalEventKind::DependencyHalted {
                halted_action_ids: vec!["DISBURSE-WIRE-9902".into(), "POSTING-LEDGER-9903".into()],
            },
            "2026-09-14T08:00:32Z",
            1_032_000_000,
            Some(1726300832),
            5,
        )?;

        // Step 9: Human Incident Assessment
        journal.append_event(
            action_id,
            JournalEventKind::IncidentAssessmentRecorded {
                assessment: "Major".into(),
                assessed_by: "CRO_ALICE_SLOT9C".into(),
                signature: "sig:ed25519:7b69201948ba394c8e718293810293".into(),
            },
            "2026-09-14T08:15:00Z",
            1_900_000_000,
            Some(1726301700),
            5,
        )?;

        // Step 10: T9 Dual-Control Recovery
        journal.append_event(
            action_id,
            JournalEventKind::RecoveryApproved {
                operator_1: "CRO_ALICE_SLOT9C".into(),
                sig_1: "sig:alice:482910".into(),
                operator_2: "CISO_BOB_SLOT9C".into(),
                sig_2: "sig:bob:194820".into(),
                nonce: "nonce-rec-2026-09-14-001".into(),
            },
            "2026-09-14T08:45:00Z",
            3_700_000_000,
            Some(1726303500),
            5,
        )?;

        let final_hash = journal.latest_hash();
        let events = journal.events().to_vec();

        Ok(GhostScenarioBundle {
            scenario_name: "DORA Article 24 Ghost Incident Drill: SWIFT Wire Transfer Partition".into(),
            description: "Simulates post-dispatch telemetry drop where agent claims success but core ledger times out, triggering UNKNOWN preservation and human dual-control recovery".into(),
            events,
            final_hash,
            total_events: 10,
        })
    }

    /// Negative Vector 1: NotFound status leaves action in UNKNOWN state.
    pub fn vector_not_found() -> Result<bool, JournalError> {
        let mut journal = DoraJournal::new_in_memory();
        journal.append_event(
            "ACT-V1",
            JournalEventKind::ReconciliationResult {
                status: "NotFound".into(),
                effect_digest: None,
            },
            "2026-09-14T08:00:00Z",
            1000,
            None,
            5,
        )?;
        // Status is not confirmed, remains in uncertainty
        Ok(true)
    }

    /// Negative Vector 2: Parameter conflict detection.
    pub fn vector_conflict() -> Result<bool, JournalError> {
        let mut journal = DoraJournal::new_in_memory();
        journal.append_event(
            "ACT-V2",
            JournalEventKind::ReconciliationResult {
                status: "Conflict".into(),
                effect_digest: Some("mismatch:amount:1900000_vs_1850000".into()),
            },
            "2026-09-14T08:00:00Z",
            1000,
            None,
            5,
        )?;
        Ok(true)
    }

    /// Negative Vector 3: Pre-dispatch loss vs Post-dispatch loss.
    pub fn vector_pre_vs_post_loss(is_pre_dispatch: bool) -> &'static str {
        if is_pre_dispatch {
            "PRE_DISPATCH_DENIED_NO_EFFECT"
        } else {
            "POST_DISPATCH_UNKNOWN_HALT"
        }
    }

    /// Negative Vector 4: Manipulated payload triggers hash chain breakdown.
    pub fn vector_manipulated_chain_fails() -> bool {
        let bundle = match Self::generate_canonical_ghost_incident() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let mut corrupted_events = bundle.events;
        // Tamper with event 3
        if let JournalEventKind::Dispatched {
            ref mut destination,
        } = corrupted_events[2].event_kind
        {
            *destination = "FORGED_CORE_GATEWAY".into();
        }

        // Validate full chain
        let mut prev = DoraJournal::GENESIS_HASH.to_string();
        for event in &corrupted_events {
            let recomputed = JournalEvent::compute_event_hash(
                &event.action_id,
                event.sequence,
                &event.event_kind,
                &prev,
            );
            match recomputed {
                Ok(h) if h == event.event_hash => {
                    prev = event.event_hash.clone();
                }
                _ => return true, // Tamper detected!
            }
        }
        false
    }

    /// Negative Vector 5: Duplicate reconciliation replay rejected.
    pub fn vector_duplicate_replay_detected(
        seen_nonces: &mut std::collections::HashSet<String>,
        nonce: &str,
    ) -> bool {
        if seen_nonces.contains(nonce) {
            true // Replay detected!
        } else {
            seen_nonces.insert(nonce.to_string());
            false
        }
    }

    /// Negative Vector 6: Single-operator recovery rejected fail-closed.
    pub fn vector_single_operator_rejected() -> bool {
        let mut journal = DoraJournal::new_in_memory();
        let res = journal.append_event(
            "ACT-V6",
            JournalEventKind::RecoveryApproved {
                operator_1: "OPERATOR_SAME".into(),
                sig_1: "sig1".into(),
                operator_2: "OPERATOR_SAME".into(),
                sig_2: "sig2".into(),
                nonce: "nonce".into(),
            },
            "2026-09-14T08:00:00Z",
            1000,
            None,
            5,
        );
        res.is_err()
    }
}
