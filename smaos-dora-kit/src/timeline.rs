//! T0–T9 Multi-Clock Timeline Reconstructor for DORA Incident Lifecycle.

use crate::journal::{JournalEvent, JournalEventKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceConfidence {
    Observed,
    Inferred,
    Missing,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceStatus {
    Complete,
    Degraded { drops: u32 },
    Incomplete { missing_phases: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelinePhase {
    pub phase_code: String, // "T0" .. "T9"
    pub phase_name: String,
    pub event_sequence: Option<u64>,
    pub source_event_ids: Vec<String>,
    pub event_hash: Option<String>,
    pub timestamp_wall_iso: Option<String>,
    pub timestamp_mono_ns: Option<u64>,
    pub timestamp_ext_time: Option<u64>,
    pub clock_uncertainty_ms: Option<u32>,
    pub confidence: EvidenceConfidence,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedTimeline {
    pub action_id: String,
    pub phases: Vec<TimelinePhase>,
    pub evidence_status: EvidenceStatus,
    pub unknown_declared_at: Option<String>,
    pub total_uncertainty_window_seconds: Option<f64>,
}

pub struct DoraTimelineReconstructor;

impl DoraTimelineReconstructor {
    pub fn reconstruct_timeline(action_id: &str, events: &[JournalEvent]) -> ReconstructedTimeline {
        let mut phases = vec![
            TimelinePhase {
                phase_code: "T0".into(),
                phase_name: "Propose".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "Pending action proposal".into(),
            },
            TimelinePhase {
                phase_code: "T1".into(),
                phase_name: "Authorize".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "Pending cryptographic authorization".into(),
            },
            TimelinePhase {
                phase_code: "T2".into(),
                phase_name: "Dispatch".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "Pending network dispatch to external system".into(),
            },
            TimelinePhase {
                phase_code: "T3".into(),
                phase_name: "Telemetry Drop".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "No telemetry anomalies detected".into(),
            },
            TimelinePhase {
                phase_code: "T4".into(),
                phase_name: "Timeout".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "No timeout reached".into(),
            },
            TimelinePhase {
                phase_code: "T5".into(),
                phase_name: "UNKNOWN Declared".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "No uncertainty state declared".into(),
            },
            TimelinePhase {
                phase_code: "T6".into(),
                phase_name: "Dependency Halt".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "Downstream execution permitted".into(),
            },
            TimelinePhase {
                phase_code: "T7".into(),
                phase_name: "Reconciliation Query".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "No external query initiated".into(),
            },
            TimelinePhase {
                phase_code: "T8".into(),
                phase_name: "Effect Observed/Reconciled".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "Pending external reconciliation outcome".into(),
            },
            TimelinePhase {
                phase_code: "T9".into(),
                phase_name: "Dual-Control Recovery".into(),
                event_sequence: None,
                source_event_ids: Vec::new(),
                event_hash: None,
                timestamp_wall_iso: None,
                timestamp_mono_ns: None,
                timestamp_ext_time: None,
                clock_uncertainty_ms: None,
                confidence: EvidenceConfidence::Missing,
                notes: "Normal operations active (no recovery required)".into(),
            },
        ];

        let mut unknown_ts: Option<String> = None;
        let mut dispatch_mono: Option<u64> = None;
        let mut recovery_mono: Option<u64> = None;

        for event in events {
            if event.action_id != action_id && !action_id.is_empty() {
                continue;
            }

            match &event.event_kind {
                JournalEventKind::Proposed { .. } => {
                    Self::populate_phase(
                        &mut phases[0],
                        event,
                        EvidenceConfidence::Observed,
                        "Proposed by agent",
                    );
                }
                JournalEventKind::Authorized { permit_id, .. } => {
                    Self::populate_phase(
                        &mut phases[1],
                        event,
                        EvidenceConfidence::Observed,
                        &format!("Permit: {}", permit_id),
                    );
                }
                JournalEventKind::Dispatched { destination } => {
                    dispatch_mono = Some(event.timestamp_mono_ns);
                    Self::populate_phase(
                        &mut phases[2],
                        event,
                        EvidenceConfidence::Observed,
                        &format!("Dispatched to: {}", destination),
                    );
                }
                JournalEventKind::AgentClaimedSuccess { .. } => {
                    // Agent claimed success without external observation -> flags T3 Telemetry Drop!
                    Self::populate_phase(
                        &mut phases[3],
                        event,
                        EvidenceConfidence::Degraded,
                        "Agent self-reported success; external ledger confirmation dropped",
                    );
                }
                JournalEventKind::ReconciliationResult { status, .. } if status == "Timeout" => {
                    Self::populate_phase(
                        &mut phases[4],
                        event,
                        EvidenceConfidence::Observed,
                        "External system of record query timed out",
                    );
                }
                JournalEventKind::UnknownDeclared { reason } => {
                    unknown_ts = Some(event.timestamp_wall_iso.clone());
                    Self::populate_phase(
                        &mut phases[5],
                        event,
                        EvidenceConfidence::Observed,
                        &format!("UNKNOWN: {}", reason),
                    );
                }
                JournalEventKind::DependencyHalted { halted_action_ids } => {
                    Self::populate_phase(
                        &mut phases[6],
                        event,
                        EvidenceConfidence::Observed,
                        &format!("Halted dependents: {:?}", halted_action_ids),
                    );
                }
                JournalEventKind::ReconciliationAttempt { adapter_id } => {
                    Self::populate_phase(
                        &mut phases[7],
                        event,
                        EvidenceConfidence::Observed,
                        &format!("Adapter: {}", adapter_id),
                    );
                }
                JournalEventKind::ReconciliationResult {
                    status,
                    effect_digest,
                } => {
                    Self::populate_phase(
                        &mut phases[8],
                        event,
                        EvidenceConfidence::Observed,
                        &format!("Status: {}, Digest: {:?}", status, effect_digest),
                    );
                }
                JournalEventKind::RecoveryApproved {
                    operator_1,
                    operator_2,
                    ..
                } => {
                    recovery_mono = Some(event.timestamp_mono_ns);
                    Self::populate_phase(
                        &mut phases[9],
                        event,
                        EvidenceConfidence::Observed,
                        &format!("Dual operators: {} and {}", operator_1, operator_2),
                    );
                }
                _ => {}
            }
        }

        let total_uncertainty_sec = match (dispatch_mono, recovery_mono) {
            (Some(d), Some(r)) if r >= d => Some((r - d) as f64 / 1_000_000_000.0),
            _ => None,
        };

        let missing_phases: Vec<String> = phases
            .iter()
            .filter(|p| p.confidence == EvidenceConfidence::Missing)
            .map(|p| p.phase_code.clone())
            .collect();

        let evidence_status = if missing_phases.is_empty() {
            EvidenceStatus::Complete
        } else {
            EvidenceStatus::Incomplete { missing_phases }
        };

        ReconstructedTimeline {
            action_id: action_id.to_string(),
            phases,
            evidence_status,
            unknown_declared_at: unknown_ts,
            total_uncertainty_window_seconds: total_uncertainty_sec,
        }
    }

    fn populate_phase(
        phase: &mut TimelinePhase,
        event: &JournalEvent,
        confidence: EvidenceConfidence,
        notes: &str,
    ) {
        phase.event_sequence = Some(event.sequence);
        phase
            .source_event_ids
            .push(format!("SEQ-{}", event.sequence));
        phase.event_hash = Some(event.event_hash.clone());
        phase.timestamp_wall_iso = Some(event.timestamp_wall_iso.clone());
        phase.timestamp_mono_ns = Some(event.timestamp_mono_ns);
        phase.timestamp_ext_time = event.timestamp_ext_time;
        phase.clock_uncertainty_ms = Some(event.clock_uncertainty_ms);
        phase.confidence = confidence;
        phase.notes = notes.to_string();
    }
}
