//! Statutory obligations, calendar engine, and authenticated reconciliation transitions.
//! Enforces EU Regulation 2022/2554 (DORA) Art. 19 and Delegated Regulation (EU) 2025/301 Art. 4(2).

use chrono::{DateTime, Datelike, Days, Duration, Months, NaiveDate, NaiveTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CalendarError {
    #[error("Invalid or unparseable timestamp: {0}")]
    InvalidDate(String),
    #[error("Non-working day search overflow exceeded limit")]
    NonWorkingDayOverflow,
    #[error("Missing intermediate report submission timestamp required for final report month calculation")]
    MissingIntermediateTimestamp,
    #[error("Calendar month calculation overflow: {0}")]
    InvalidMonthOffset(String),
    #[error("Cryptographic signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    #[error("Invalid public key or signature format: {0}")]
    CryptoError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    /// Credit institutions subject to DORA and strict non-adjustment rules
    CreditInstitution,
    /// Critical / Essential entities subject to non-adjustment under RTS 2025/301 Art. 4(2)
    EssentialOrImportantEntity,
    /// Other regulated financial entities
    OtherFinancialEntity,
    /// ICT Third-Party Service Providers
    ICTThirdParty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationType {
    /// DORA Article 19(4)(a) Initial Notification: min(T_class + 4h, T_aware + 24h)
    InitialNotification,
    /// DORA Article 19(4)(b) Intermediate Report: T_class + 72h
    IntermediateReport,
    /// DORA Article 19(4)(c) Final Report: 1 month from latest intermediate report
    FinalReport,
}

/// Versioned, immutable Member State Calendar encapsulating statutory working-day rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberStateCalendar {
    pub calendar_id: String,
    pub member_state: String,
    pub year: i32,
    holidays: HashSet<NaiveDate>,
}

impl MemberStateCalendar {
    /// Constructs default Czech Republic 2026 calendar (CZ-2026-v1).
    pub fn czech_2026() -> Self {
        let mut holidays = HashSet::new();
        let y = 2026;
        // Statutory Czech Public Holidays (Zákon č. 245/2000 Sb.)
        let holiday_dates = [
            (1, 1),   // New Year / Restoration Day
            (4, 3),   // Good Friday 2026
            (4, 6),   // Easter Monday 2026
            (5, 1),   // Labour Day
            (5, 8),   // Liberation Day
            (7, 5),   // Saints Cyril & Methodius Day
            (7, 6),   // Jan Hus Day
            (9, 28),  // Statehood Day (St. Wenceslas)
            (10, 28), // Independent Czechoslovak State Day
            (11, 17), // Struggle for Freedom & Democracy Day
            (12, 24), // Christmas Eve
            (12, 25), // Christmas Day
            (12, 26), // St. Stephen's Day
        ];

        for (m, d) in holiday_dates {
            if let Some(date) = NaiveDate::from_ymd_opt(y, m, d) {
                holidays.insert(date);
            }
        }

        Self {
            calendar_id: "CZ-2026-v1".into(),
            member_state: "CZ".into(),
            year: y,
            holidays,
        }
    }

    /// Evaluates whether a given calendar date is a statutory working day.
    pub fn is_working_day(&self, date: NaiveDate) -> bool {
        let weekday = date.weekday();
        if weekday == chrono::Weekday::Sat || weekday == chrono::Weekday::Sun {
            return false;
        }
        !self.holidays.contains(&date)
    }

    /// Computes the next working-day statutory deadline, snapping strictly to 12:00:00 UTC.
    pub fn next_working_day_deadline(
        &self,
        target: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, CalendarError> {
        let mut curr_date = target.date_naive();

        // If target is already a working day, return as-is
        if self.is_working_day(curr_date) {
            return Ok(target);
        }

        // Loop forward to find the next verified working day
        for _ in 0..30 {
            curr_date = match curr_date.checked_add_days(Days::new(1)) {
                Some(d) => d,
                None => return Err(CalendarError::NonWorkingDayOverflow),
            };

            if self.is_working_day(curr_date) {
                let noon = match NaiveTime::from_hms_opt(12, 0, 0) {
                    Some(t) => t,
                    None => return Err(CalendarError::InvalidDate("12:00:00".into())),
                };
                let naive_dt = curr_date.and_time(noon);
                return Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc));
            }
        }

        Err(CalendarError::NonWorkingDayOverflow)
    }
}

impl Default for MemberStateCalendar {
    fn default() -> Self {
        Self::czech_2026()
    }
}

/// Fully auditable statutory deadline calculation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalculatedDeadline {
    pub obligation_type: ObligationType,
    pub raw_deadline: DateTime<Utc>,
    pub adjusted_deadline: DateTime<Utc>,
    pub adjustment_applied: bool,
    pub adjustment_reason: Option<String>,
    pub legal_basis: String,
    pub calendar_id: String,
}

/// Deterministic statutory deadline calculator under DORA and RTS 2025/301.
pub struct StatutoryDeadlineEngine {
    pub calendar: MemberStateCalendar,
}

impl StatutoryDeadlineEngine {
    pub fn new(calendar: MemberStateCalendar) -> Self {
        Self { calendar }
    }

    pub fn with_default_calendar() -> Self {
        Self {
            calendar: MemberStateCalendar::default(),
        }
    }

    /// Computes statutory DORA deadline incorporating Dual-Threshold and RTS 2025/301 Art. 4(2) non-adjustment rules.
    pub fn calculate_deadline(
        &self,
        entity_type: EntityType,
        obligation_type: ObligationType,
        awareness_timestamp: Option<DateTime<Utc>>,
        classification_timestamp: Option<DateTime<Utc>>,
        latest_intermediate_timestamp: Option<DateTime<Utc>>,
    ) -> Result<CalculatedDeadline, CalendarError> {
        let (raw_deadline, legal_basis) = match obligation_type {
            ObligationType::InitialNotification => {
                let d_class = classification_timestamp.map(|t| t + Duration::hours(4));
                let d_aware = awareness_timestamp.map(|t| t + Duration::hours(24));

                match (d_class, d_aware) {
                    (Some(c), Some(a)) => {
                        let earliest = if c < a { c } else { a };
                        (
                            earliest,
                            "DORA Art. 19(4)(a) - min(T_class + 4h, T_aware + 24h)".to_string(),
                        )
                    }
                    (Some(c), None) => (
                        c,
                        "DORA Art. 19(4)(a) - T_class + 4h (Awareness pending)".to_string(),
                    ),
                    (None, Some(a)) => (
                        a,
                        "DORA Art. 19(1) - T_aware + 24h (Classification pending)".to_string(),
                    ),
                    (None, None) => {
                        return Err(CalendarError::InvalidDate(
                            "At least awareness or classification timestamp required for Initial Notification".into(),
                        ));
                    }
                }
            }
            ObligationType::IntermediateReport => {
                let class_time = classification_timestamp.ok_or_else(|| {
                    CalendarError::InvalidDate(
                        "Classification timestamp required for Intermediate Report".into(),
                    )
                })?;
                (
                    class_time + Duration::hours(72),
                    "DORA Art. 19(4)(b) - T_class + 72h".to_string(),
                )
            }
            ObligationType::FinalReport => {
                let intermediate_time = latest_intermediate_timestamp
                    .ok_or(CalendarError::MissingIntermediateTimestamp)?;

                // Calendar-aware 1-month addition using chrono::Months
                let raw = match intermediate_time.checked_add_months(Months::new(1)) {
                    Some(dt) => dt,
                    None => {
                        return Err(CalendarError::InvalidMonthOffset(
                            "Failed to calculate 1 calendar month from intermediate report".into(),
                        ));
                    }
                };

                (
                    raw,
                    "DORA Art. 19(4)(c) - Exactly 1 calendar month from latest intermediate report"
                        .to_string(),
                )
            }
        };

        // Enforce Delegated Regulation (EU) 2025/301 Art. 4(2) Non-Adjustment Exemption:
        // CreditInstitutions and EssentialOrImportantEntities receive NO weekend/holiday extension for Initial & Intermediate!
        let is_exempt_from_adjustment = (entity_type == EntityType::CreditInstitution
            || entity_type == EntityType::EssentialOrImportantEntity)
            && (obligation_type == ObligationType::InitialNotification
                || obligation_type == ObligationType::IntermediateReport);

        if is_exempt_from_adjustment {
            return Ok(CalculatedDeadline {
                obligation_type,
                raw_deadline,
                adjusted_deadline: raw_deadline,
                adjustment_applied: false,
                adjustment_reason: Some(
                    "Delegated Regulation (EU) 2025/301 Art. 4(2) non-adjustment exemption enforced (Credit Institution / Essential Entity: no weekend or holiday extension)"
                        .into(),
                ),
                legal_basis,
                calendar_id: self.calendar.calendar_id.clone(),
            });
        }

        // For other entities or for FinalReport: roll to next working day 12:00:00 UTC if falling on non-working day
        if !self.calendar.is_working_day(raw_deadline.date_naive()) {
            let adjusted = self.calendar.next_working_day_deadline(raw_deadline)?;
            Ok(CalculatedDeadline {
                obligation_type,
                raw_deadline,
                adjusted_deadline: adjusted,
                adjustment_applied: true,
                adjustment_reason: Some(format!(
                    "Deadline fell on non-working day ({}); rolled to next working day 12:00:00 UTC pursuant to standard Member State rules",
                    raw_deadline.date_naive()
                )),
                legal_basis,
                calendar_id: self.calendar.calendar_id.clone(),
            })
        } else {
            Ok(CalculatedDeadline {
                obligation_type,
                raw_deadline,
                adjusted_deadline: raw_deadline,
                adjustment_applied: false,
                adjustment_reason: None,
                legal_basis,
                calendar_id: self.calendar.calendar_id.clone(),
            })
        }
    }
}

impl Default for StatutoryDeadlineEngine {
    fn default() -> Self {
        Self::with_default_calendar()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconciliationOutcome {
    Confirmed,
    Refused,
}

impl ReconciliationOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::Refused => "REFUSED",
        }
    }
}

/// Cryptographically authenticated reconciliation event required to mutate state from UNKNOWN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedReconciliationEvent {
    pub event_id: String,
    pub action_id: String,
    pub outcome: ReconciliationOutcome,
    pub timestamp_iso: String,
    pub payload_digest: String,
    pub signer_pubkey_hex: String,
    pub signature_hex: String,
    pub sequence: u64,
    pub previous_event_digest: String,
    pub event_digest: String,
}

impl AuthenticatedReconciliationEvent {
    /// Canonical signing payload construction.
    pub fn build_signing_bytes(
        event_id: &str,
        action_id: &str,
        outcome: ReconciliationOutcome,
        payload_digest: &str,
        sequence: u64,
        previous_event_digest: &str,
    ) -> Vec<u8> {
        let msg = format!(
            "{}:{}:{}:{}:{}:{}",
            event_id,
            action_id,
            outcome.as_str(),
            payload_digest,
            sequence,
            previous_event_digest
        );
        msg.into_bytes()
    }

    /// Computes the event digest (SHA-256).
    pub fn compute_digest(
        event_id: &str,
        action_id: &str,
        outcome: ReconciliationOutcome,
        payload_digest: &str,
        sequence: u64,
        previous_event_digest: &str,
    ) -> String {
        let msg = Self::build_signing_bytes(
            event_id,
            action_id,
            outcome,
            payload_digest,
            sequence,
            previous_event_digest,
        );
        let mut hasher = Sha256::new();
        hasher.update(&msg);
        hex::encode(hasher.finalize())
    }

    /// Verifies the Ed25519 cryptographic signature.
    pub fn verify_signature(&self) -> Result<bool, CalendarError> {
        let pubkey_bytes = hex::decode(&self.signer_pubkey_hex)
            .map_err(|e| CalendarError::CryptoError(format!("Invalid public key hex: {}", e)))?;
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| CalendarError::CryptoError(format!("Invalid signature hex: {}", e)))?;

        if pubkey_bytes.len() != 32 {
            return Err(CalendarError::CryptoError(
                "Public key must be 32 bytes".into(),
            ));
        }
        if sig_bytes.len() != 64 {
            return Err(CalendarError::CryptoError(
                "Signature must be 64 bytes".into(),
            ));
        }

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pubkey_bytes);

        let verifying_key = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| CalendarError::CryptoError(format!("Invalid verifying key: {}", e)))?;

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| CalendarError::CryptoError(format!("Invalid signature format: {}", e)))?;

        let signed_msg = Self::build_signing_bytes(
            &self.event_id,
            &self.action_id,
            self.outcome,
            &self.payload_digest,
            self.sequence,
            &self.previous_event_digest,
        );

        match verifying_key.verify(&signed_msg, &signature) {
            Ok(()) => Ok(true),
            Err(e) => Err(CalendarError::SignatureVerificationFailed(e.to_string())),
        }
    }
}

/// EU 2024/1772 Article 8 Direct Economic Loss Evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectLossPartition {
    /// Gross Nominal Unresolved Exposure in integer minor units (EUR cents)
    pub gross_nominal_unresolved_cents: u64,
    /// Direct internal recovery costs / damages in integer minor units (EUR cents)
    pub direct_internal_costs_cents: u64,
    /// DORA Article 8 threshold in integer minor units (€100,000 = 10_000_000 cents)
    pub article_8_threshold_cents: u64,
    /// Status: EvaluatedBelowThreshold until internal losses quantified
    pub article_8_status: Article8Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Article8Status {
    EvaluatedBelowThreshold,
    QuantifiedExceedsThreshold,
    AwaitingFinanceQuantification,
}

impl DirectLossPartition {
    pub const DEFAULT_THRESHOLD_CENTS: u64 = 10_000_000; // €100,000.00 in EUR cents

    pub fn new(gross_nominal_cents: u64) -> Self {
        Self {
            gross_nominal_unresolved_cents: gross_nominal_cents,
            direct_internal_costs_cents: 0,
            article_8_threshold_cents: Self::DEFAULT_THRESHOLD_CENTS,
            article_8_status: Article8Status::EvaluatedBelowThreshold,
        }
    }

    pub fn set_internal_costs(&mut self, direct_costs_cents: u64) {
        self.direct_internal_costs_cents = direct_costs_cents;
        if direct_costs_cents >= self.article_8_threshold_cents {
            self.article_8_status = Article8Status::QuantifiedExceedsThreshold;
        } else {
            self.article_8_status = Article8Status::EvaluatedBelowThreshold;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_czech_calendar_working_days() {
        let cal = MemberStateCalendar::czech_2026();
        // 2026-01-01 is New Year (Holiday)
        let new_year = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        assert!(!cal.is_working_day(new_year));

        // 2026-01-02 is Friday (Working day)
        let fri = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
        assert!(cal.is_working_day(fri));

        // 2026-01-03 is Saturday (Weekend)
        let sat = NaiveDate::from_ymd_opt(2026, 1, 3).unwrap();
        assert!(!cal.is_working_day(sat));
    }

    #[test]
    fn test_rts_2025_301_art_4_2_non_adjustment_for_credit_institutions() {
        let engine = StatutoryDeadlineEngine::with_default_calendar();
        // Friday 2026-01-02 at 22:00 UTC classification
        let class_time = Utc.with_ymd_and_hms(2026, 1, 2, 22, 0, 0).unwrap();

        // 4h deadline falls on Saturday 2026-01-03 at 02:00 UTC
        let deadline = engine
            .calculate_deadline(
                EntityType::CreditInstitution,
                ObligationType::InitialNotification,
                Some(class_time),
                Some(class_time),
                None,
            )
            .unwrap();

        // Must NOT roll forward for CreditInstitution!
        assert!(!deadline.adjustment_applied);
        assert_eq!(deadline.raw_deadline, deadline.adjusted_deadline);
        assert_eq!(
            deadline.adjusted_deadline,
            Utc.with_ymd_and_hms(2026, 1, 3, 2, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_weekend_roll_for_other_entities() {
        let engine = StatutoryDeadlineEngine::with_default_calendar();
        // Friday 2026-01-02 at 22:00 UTC classification
        let class_time = Utc.with_ymd_and_hms(2026, 1, 2, 22, 0, 0).unwrap();

        let deadline = engine
            .calculate_deadline(
                EntityType::OtherFinancialEntity,
                ObligationType::InitialNotification,
                Some(class_time),
                Some(class_time),
                None,
            )
            .unwrap();

        // Other financial entities roll to next working day 12:00 UTC (Monday 2026-01-05 12:00:00 UTC)
        assert!(deadline.adjustment_applied);
        assert_eq!(
            deadline.adjusted_deadline,
            Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_calendar_aware_final_report_month_math() {
        let engine = StatutoryDeadlineEngine::with_default_calendar();
        // Intermediate report submitted Jan 31, 2026 at 10:00 UTC
        let intermediate_time = Utc.with_ymd_and_hms(2026, 1, 31, 10, 0, 0).unwrap();

        let deadline = engine
            .calculate_deadline(
                EntityType::CreditInstitution,
                ObligationType::FinalReport,
                None,
                None,
                Some(intermediate_time),
            )
            .unwrap();

        // In 2026 (non-leap year), Feb has 28 days -> Jan 31 + 1 month = Feb 28, 2026 (Saturday)
        // Since Feb 28 is Saturday, and FinalReport rolls for all entities: rolls to Mon Mar 2, 2026 12:00 UTC
        assert_eq!(
            deadline.raw_deadline.date_naive(),
            NaiveDate::from_ymd_opt(2026, 2, 28).unwrap()
        );
        assert!(deadline.adjustment_applied);
        assert_eq!(
            deadline.adjusted_deadline,
            Utc.with_ymd_and_hms(2026, 3, 2, 12, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_authenticated_reconciliation_event_signature() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.as_bytes());

        let event_id = "REC-EVT-001";
        let action_id = "ACT-SWIFT-9901";
        let outcome = ReconciliationOutcome::Confirmed;
        let payload_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let sequence = 6;
        let prev_digest = "0000000000000000000000000000000000000000000000000000000000000000";

        let msg = AuthenticatedReconciliationEvent::build_signing_bytes(
            event_id,
            action_id,
            outcome,
            payload_digest,
            sequence,
            prev_digest,
        );

        use ed25519_dalek::Signer;
        let sig = signing_key.sign(&msg);
        let sig_hex = hex::encode(sig.to_bytes());
        let digest = AuthenticatedReconciliationEvent::compute_digest(
            event_id,
            action_id,
            outcome,
            payload_digest,
            sequence,
            prev_digest,
        );

        let event = AuthenticatedReconciliationEvent {
            event_id: event_id.into(),
            action_id: action_id.into(),
            outcome,
            timestamp_iso: "2026-09-14T08:00:30Z".into(),
            payload_digest: payload_digest.into(),
            signer_pubkey_hex: pubkey_hex,
            signature_hex: sig_hex,
            sequence,
            previous_event_digest: prev_digest.into(),
            event_digest: digest,
        };

        assert!(event.verify_signature().unwrap());
    }
}
