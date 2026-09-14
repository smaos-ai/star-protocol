//! RFC 8785 Canonical JCS and Merkle Hash-Chained Journal for SMAOS DORA Incident Engine.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JournalError {
    #[error(
        "Hash chain corrupted at sequence {sequence}: expected {expected}, computed {computed}"
    )]
    HashChainCorrupted {
        sequence: u64,
        expected: String,
        computed: String,
    },
    #[error("Sequence gap detected: expected sequence {expected}, got {actual}")]
    SequenceGap { expected: u64, actual: u64 },
    #[error("JCS serialization failed: {0}")]
    JcsFailed(String),
    #[error("Clock anomaly detected: {0}")]
    ClockAnomaly(String),
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("Invalid event payload: {0}")]
    InvalidPayload(String),
    #[error(
        "Two-person recovery violation: operator 1 ({op1}) and operator 2 ({op2}) must be distinct"
    )]
    SingleOperatorViolation { op1: String, op2: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub enum JournalEventKind {
    Proposed {
        action_id: String,
        risk_tier: String,
    },
    Authorized {
        permit_id: String,
        scope: String,
    },
    Dispatched {
        destination: String,
    },
    AgentClaimedSuccess {
        claim_digest: String,
    },
    ExternalEffectObserved {
        effect_digest: String,
    },
    ReconciliationAttempt {
        adapter_id: String,
    },
    ReconciliationResult {
        status: String,
        effect_digest: Option<String>,
    },
    UnknownDeclared {
        reason: String,
    },
    DependencyHalted {
        halted_action_ids: Vec<String>,
    },
    IncidentAssessmentRecorded {
        assessment: String, // "Major" | "NonMajor" | "Pending"
        assessed_by: String,
        signature: String,
    },
    RecoveryRequested {
        incident_id: String,
        scope: String,
    },
    RecoveryApproved {
        operator_1: String,
        sig_1: String,
        operator_2: String,
        sig_2: String,
        nonce: String,
    },
    LessonsLearnedRecorded {
        root_cause: String,
        remediation_ticket: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalEvent {
    pub sequence: u64,
    pub action_id: String,
    pub event_kind: JournalEventKind,
    pub timestamp_wall_iso: String,
    pub timestamp_mono_ns: u64,
    pub timestamp_ext_time: Option<u64>,
    pub clock_uncertainty_ms: u32,
    pub prev_hash: String,
    pub event_hash: String,
}

impl JournalEvent {
    /// Serializes the event body to RFC 8785 Canonical JSON (JCS).
    pub fn to_jcs_bytes(&self) -> Result<Vec<u8>, JournalError> {
        // serde_json serializer with sorted keys for canonical formatting
        let val = serde_json::to_value(&self.event_kind)
            .map_err(|e| JournalError::JcsFailed(e.to_string()))?;
        let canonical_str = canonicalize_json_value(&val);
        Ok(canonical_str.into_bytes())
    }

    /// Computes the SHA-256 Merkle hash for the event:
    /// `event_hash = SHA256(action_id || sequence || JCS(state) || prev_hash)`
    pub fn compute_event_hash(
        action_id: &str,
        sequence: u64,
        event_kind: &JournalEventKind,
        prev_hash: &str,
    ) -> Result<String, JournalError> {
        let val =
            serde_json::to_value(event_kind).map_err(|e| JournalError::JcsFailed(e.to_string()))?;
        let jcs = canonicalize_json_value(&val);

        let mut hasher = Sha256::new();
        hasher.update(action_id.as_bytes());
        hasher.update(sequence.to_be_bytes());
        hasher.update(jcs.as_bytes());
        hasher.update(prev_hash.as_bytes());

        Ok(hex::encode(hasher.finalize()))
    }
}

/// Recursive RFC 8785 JSON Canonicalization helper
fn canonicalize_json_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_json_value).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(map) => {
            let mut sorted_keys: Vec<&String> = map.keys().collect();
            sorted_keys.sort();
            let pairs: Vec<String> = sorted_keys
                .into_iter()
                .map(|k| {
                    let key_str = serde_json::to_string(k).unwrap_or_else(|_| "\"\"".to_string());
                    let val_str = canonicalize_json_value(&map[k]);
                    format!("{}:{}", key_str, val_str)
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

pub struct DoraJournal {
    events: Vec<JournalEvent>,
    file_path: Option<String>,
}

impl DoraJournal {
    pub const GENESIS_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn new_in_memory() -> Self {
        Self {
            events: Vec::new(),
            file_path: None,
        }
    }

    pub fn open_or_create<P: AsRef<Path>>(path: P) -> Result<Self, JournalError> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let mut journal = Self {
            events: Vec::new(),
            file_path: Some(path_str.clone()),
        };

        if Path::new(&path_str).exists() {
            let file = File::open(&path_str)?;
            let reader = BufReader::new(file);
            for (line_num, line) in reader.lines().enumerate() {
                let l = line?;
                if l.trim().is_empty() {
                    continue;
                }
                let event: JournalEvent = serde_json::from_str(&l).map_err(|e| {
                    JournalError::InvalidPayload(format!("Line {}: {}", line_num + 1, e))
                })?;
                journal.validate_and_push(event)?;
            }
        }

        Ok(journal)
    }

    pub fn latest_hash(&self) -> String {
        self.events
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_else(|| Self::GENESIS_HASH.to_string())
    }

    pub fn latest_sequence(&self) -> u64 {
        self.events.last().map(|e| e.sequence).unwrap_or(0)
    }

    pub fn append_event(
        &mut self,
        action_id: &str,
        event_kind: JournalEventKind,
        timestamp_wall_iso: &str,
        timestamp_mono_ns: u64,
        timestamp_ext_time: Option<u64>,
        clock_uncertainty_ms: u32,
    ) -> Result<JournalEvent, JournalError> {
        // Enforce two-person recovery rule
        if let JournalEventKind::RecoveryApproved {
            ref operator_1,
            ref operator_2,
            ..
        } = event_kind
        {
            if operator_1 == operator_2 {
                return Err(JournalError::SingleOperatorViolation {
                    op1: operator_1.clone(),
                    op2: operator_2.clone(),
                });
            }
        }

        let next_seq = self.latest_sequence() + 1;
        let prev_hash = self.latest_hash();
        let event_hash =
            JournalEvent::compute_event_hash(action_id, next_seq, &event_kind, &prev_hash)?;

        let event = JournalEvent {
            sequence: next_seq,
            action_id: action_id.to_string(),
            event_kind,
            timestamp_wall_iso: timestamp_wall_iso.to_string(),
            timestamp_mono_ns,
            timestamp_ext_time,
            clock_uncertainty_ms,
            prev_hash,
            event_hash,
        };

        if let Some(ref path) = self.file_path {
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            let serialized = serde_json::to_string(&event)
                .map_err(|e| JournalError::JcsFailed(e.to_string()))?;
            writeln!(file, "{}", serialized)?;
            // Emulate synchronous = FULL with sync_all
            file.sync_all()?;
        }

        self.events.push(event.clone());
        Ok(event)
    }

    fn validate_and_push(&mut self, event: JournalEvent) -> Result<(), JournalError> {
        let expected_seq = self.latest_sequence() + 1;
        if event.sequence != expected_seq {
            return Err(JournalError::SequenceGap {
                expected: expected_seq,
                actual: event.sequence,
            });
        }

        let expected_prev_hash = self.latest_hash();
        if event.prev_hash != expected_prev_hash {
            return Err(JournalError::HashChainCorrupted {
                sequence: event.sequence,
                expected: expected_prev_hash,
                computed: event.prev_hash,
            });
        }

        let recomputed_hash = JournalEvent::compute_event_hash(
            &event.action_id,
            event.sequence,
            &event.event_kind,
            &event.prev_hash,
        )?;
        if event.event_hash != recomputed_hash {
            return Err(JournalError::HashChainCorrupted {
                sequence: event.sequence,
                expected: recomputed_hash,
                computed: event.event_hash,
            });
        }

        self.events.push(event);
        Ok(())
    }

    pub fn events(&self) -> &[JournalEvent] {
        &self.events
    }

    /// Verifies the complete hash chain from sequence 1 to N.
    pub fn verify_full_chain(&self) -> Result<(), JournalError> {
        let mut prev = Self::GENESIS_HASH.to_string();
        for (idx, event) in self.events.iter().enumerate() {
            let expected_seq = (idx as u64) + 1;
            if event.sequence != expected_seq {
                return Err(JournalError::SequenceGap {
                    expected: expected_seq,
                    actual: event.sequence,
                });
            }
            if event.prev_hash != prev {
                return Err(JournalError::HashChainCorrupted {
                    sequence: event.sequence,
                    expected: prev,
                    computed: event.prev_hash.clone(),
                });
            }
            let recomputed = JournalEvent::compute_event_hash(
                &event.action_id,
                event.sequence,
                &event.event_kind,
                &event.prev_hash,
            )?;
            if event.event_hash != recomputed {
                return Err(JournalError::HashChainCorrupted {
                    sequence: event.sequence,
                    expected: recomputed,
                    computed: event.event_hash.clone(),
                });
            }
            prev = event.event_hash.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_jcs_and_hash_chain_continuity() {
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
            .unwrap();

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
            .unwrap();

        assert_eq!(e2.sequence, 2);
        assert_eq!(e2.prev_hash, e1.event_hash);

        assert!(journal.verify_full_chain().is_ok());
    }

    #[test]
    fn test_two_person_recovery_enforcement() {
        let mut journal = DoraJournal::new_in_memory();
        let res = journal.append_event(
            "ACT-RECOVERY",
            JournalEventKind::RecoveryApproved {
                operator_1: "OPERATOR_ALICE".into(),
                sig_1: "sig1".into(),
                operator_2: "OPERATOR_ALICE".into(), // VIOLATION
                sig_2: "sig2".into(),
                nonce: "nonce123".into(),
            },
            "2026-09-14T08:30:00Z",
            5000,
            None,
            5,
        );

        assert!(matches!(
            res,
            Err(JournalError::SingleOperatorViolation { .. })
        ));
    }
}
