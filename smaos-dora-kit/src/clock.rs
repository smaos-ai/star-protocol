//! DORA Article 19 Regulatory Countdown Clock Engine.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentClockState {
    NoAwarenessRecorded,
    AwarenessRecordedClassificationPending,
    MajorClassificationRecorded,
    NonMajorClassificationRecorded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoraDeadline {
    pub deadline_name: String,
    pub statutory_reference: String,
    pub target_timestamp_iso: String,
    pub remaining_seconds: i64,
    pub is_overdue: bool,
    pub calculation_basis: String,
    pub responsible_owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoraCountdownStatus {
    pub clock_state: IncidentClockState,
    pub awareness_timestamp_iso: Option<String>,
    pub classification_timestamp_iso: Option<String>,
    pub assessed_by: Option<String>,
    pub is_classification_pending: bool,
    pub deadlines: Vec<DoraDeadline>,
}

pub struct DoraClockEngine;

impl DoraClockEngine {
    /// Evaluates the regulatory countdown state based on awareness and human assessment timestamps.
    pub fn evaluate_clocks(
        awareness_iso: Option<&str>,
        assessment_iso: Option<&str>,
        assessment_type: Option<&str>,
        assessed_by: Option<&str>,
        current_time: DateTime<Utc>,
    ) -> DoraCountdownStatus {
        let awareness_dt = awareness_iso.and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        });
        let assessment_dt = assessment_iso.and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        });

        let mut deadlines = Vec::new();

        let awareness_time = match awareness_dt {
            Some(dt) => dt,
            None => {
                return DoraCountdownStatus {
                    clock_state: IncidentClockState::NoAwarenessRecorded,
                    awareness_timestamp_iso: None,
                    classification_timestamp_iso: None,
                    assessed_by: None,
                    is_classification_pending: false,
                    deadlines: Vec::new(),
                };
            }
        };

        // 1. 24h Awareness Window (always active from awareness time T5)
        let awareness_deadline = awareness_time + Duration::hours(24);
        let rem_awareness = (awareness_deadline - current_time).num_seconds();
        deadlines.push(DoraDeadline {
            deadline_name: "24h Incident Awareness Window".into(),
            statutory_reference: "DORA Article 19(1) - Initial Awareness Window".into(),
            target_timestamp_iso: awareness_deadline.to_rfc3339(),
            remaining_seconds: rem_awareness,
            is_overdue: rem_awareness < 0,
            calculation_basis: format!(
                "Awareness timestamp ({}) + 24 hours",
                awareness_time.to_rfc3339()
            ),
            responsible_owner: "Head of ICT Incident Management".into(),
        });

        // If no assessment or assessment is Pending
        let is_major = assessment_type
            .map(|t| t.eq_ignore_ascii_case("Major"))
            .unwrap_or(false);

        if assessment_dt.is_none() || !is_major {
            let state = if assessment_type
                .map(|t| t.eq_ignore_ascii_case("NonMajor"))
                .unwrap_or(false)
            {
                IncidentClockState::NonMajorClassificationRecorded
            } else {
                IncidentClockState::AwarenessRecordedClassificationPending
            };

            return DoraCountdownStatus {
                clock_state: state,
                awareness_timestamp_iso: Some(awareness_time.to_rfc3339()),
                classification_timestamp_iso: assessment_dt.map(|dt| dt.to_rfc3339()),
                assessed_by: assessed_by.map(|s| s.to_string()),
                is_classification_pending: state
                    == IncidentClockState::AwarenessRecordedClassificationPending,
                deadlines,
            };
        }

        // Assessment is Major -> calculate 4h, 72h, and 30d deadlines from classification time!
        let class_time = match assessment_dt {
            Some(dt) => dt,
            None => {
                return DoraCountdownStatus {
                    clock_state: IncidentClockState::AwarenessRecordedClassificationPending,
                    awareness_timestamp_iso: Some(awareness_time.to_rfc3339()),
                    classification_timestamp_iso: None,
                    assessed_by: assessed_by.map(|s| s.to_string()),
                    is_classification_pending: true,
                    deadlines,
                };
            }
        };

        // 2. 4h Initial Notification Window
        let notif_deadline = class_time + Duration::hours(4);
        let rem_notif = (notif_deadline - current_time).num_seconds();
        deadlines.push(DoraDeadline {
            deadline_name: "4h Initial Notification Window".into(),
            statutory_reference:
                "DORA Article 19(4)(a) - Initial Notification to Competent Authority".into(),
            target_timestamp_iso: notif_deadline.to_rfc3339(),
            remaining_seconds: rem_notif,
            is_overdue: rem_notif < 0,
            calculation_basis: format!(
                "Major classification timestamp ({}) + 4 hours",
                class_time.to_rfc3339()
            ),
            responsible_owner: "Chief Information Security Officer (CISO)".into(),
        });

        // 3. 72h Intermediate Report Deadline
        let inter_deadline = class_time + Duration::hours(72);
        let rem_inter = (inter_deadline - current_time).num_seconds();
        deadlines.push(DoraDeadline {
            deadline_name: "72h Intermediate Progress Report".into(),
            statutory_reference: "DORA Article 19(4)(b) - Intermediate Report on Mitigation".into(),
            target_timestamp_iso: inter_deadline.to_rfc3339(),
            remaining_seconds: rem_inter,
            is_overdue: rem_inter < 0,
            calculation_basis: format!(
                "Major classification timestamp ({}) + 72 hours",
                class_time.to_rfc3339()
            ),
            responsible_owner: "Incident Response Lead".into(),
        });

        // 4. 30d Final Root-Cause Report Deadline
        let final_deadline = class_time + Duration::days(30);
        let rem_final = (final_deadline - current_time).num_seconds();
        deadlines.push(DoraDeadline {
            deadline_name: "30-Day Final Root-Cause Report".into(),
            statutory_reference: "DORA Article 19(4)(c) - Final Report with Root-Cause Analysis"
                .into(),
            target_timestamp_iso: final_deadline.to_rfc3339(),
            remaining_seconds: rem_final,
            is_overdue: rem_final < 0,
            calculation_basis: format!(
                "Major classification timestamp ({}) + 30 calendar days",
                class_time.to_rfc3339()
            ),
            responsible_owner: "Head of Operational Risk & Audit Committee".into(),
        });

        DoraCountdownStatus {
            clock_state: IncidentClockState::MajorClassificationRecorded,
            awareness_timestamp_iso: Some(awareness_time.to_rfc3339()),
            classification_timestamp_iso: Some(class_time.to_rfc3339()),
            assessed_by: assessed_by.map(|s| s.to_string()),
            is_classification_pending: false,
            deadlines,
        }
    }
}
