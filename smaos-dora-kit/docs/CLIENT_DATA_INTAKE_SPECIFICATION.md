# SMAOS 1-Page Client Data Intake Specification
**Document Version:** 1.0.5 &bull; **Engagement Type:** 5-Day Unknown Exposure Review  
**Audience:** Partner Solution Architects, Client Lead Engineers, Head of Core Banking / Platform Architecture  
**Execution Paradigm:** 100% On-Premise / Air-Gapped CLI Execution (`smaos-intake-check` & `smaos-review`)

---

## 1. Objective & Scope of Extraction
To evaluate historical agent-action confirmation integrity and DORA Article 18/19 reporting gaps, the client provides **24 to 72 hours** of historical production execution and downstream reconciliation logs (up to 250,000 records).

> **Important:** The review is strictly read-only and performed offline. No production write access or live network connections are required.

---

## 2. Required Log Schema (JSON Lines format: `.jsonl`)

The extraction must be provided as a single `.jsonl` file where each line is an independent JSON object matching one of the following schema definitions:

### A. Event Rows (`"row_type": "EVENT"`)
Captures an autonomous agent's proposed, authorized, or dispatched financial or data mutation.
```json
{
  "row_type": "EVENT",
  "action_id": "ACT-SWIFT-10023",
  "nonce": "NONCE-847291",
  "event_kind": "Dispatched",
  "amount_cents": 12500000,
  "currency": "EUR",
  "target_adapter": "SWIFT_ALLIANCE_GATEWAY",
  "timestamp_iso": "2026-09-02T10:14:02.120Z"
}
```

### B. State Transition Rows (`"row_type": "STATE_TRANSITION"`)
Captures downstream confirmations, gateway timeouts, or reconciliation errors.
```json
{
  "row_type": "STATE_TRANSITION",
  "action_id": "ACT-SWIFT-10023",
  "nonce": "NONCE-847292",
  "target_state": "UNKNOWN",
  "amount_cents": 12500000,
  "reason": "HTTP 504 Gateway Timeout from downstream core banking settlement adapter",
  "timestamp_iso": "2026-09-02T10:14:32.450Z"
}
```

---

## 3. Mandatory Field Dictionary

| Field | Type | Required | Description / Constraints |
| :--- | :--- | :---: | :--- |
| `row_type` | String | **YES** | One of: `"EVENT"`, `"STATE_TRANSITION"`, `"CONFLICT"`. |
| `action_id` | String | **YES** | Unique persistent transaction identifier (e.g. `ACT-SWIFT-9901`). |
| `nonce` | String | **YES** | Monotonic dispatch sequence nonce used to detect duplicate retransmissions. |
| `amount_cents` | Integer | **YES** | Monetary value in **integer minor units** (e.g., €125,000.00 = `12500000`). Float values are prohibited. |
| `currency` | String | **YES** | ISO 4217 currency code (e.g., `"EUR"`, `"CZK"`, `"USD"`). |
| `target_state` | String | Cond. | Target state for transitions: `"CONFIRMED"`, `"REFUSED"`, or `"UNKNOWN"`. |
| `timestamp_iso` | String | **YES** | ISO 8601 UTC timestamp (e.g., `"2026-09-02T10:14:02.120Z"`). |

---

## 4. Client Sanitization & Data Protection Protocol

To avoid transferring Personally Identifiable Information (PII) or customer banking secrets:
1. **Mask Account Numbers (IBANs):** Replace IBANs/BICs with synthetic hashes (e.g., `SHA256(IBAN)[:16]`).
2. **Exclude Counterparty Names:** Do not include raw beneficiary names, customer addresses, or narrative free text.
3. **Preserve Exact Nonces & Timestamps:** Monotonic sequencing and millisecond timestamps must be preserved verbatim for Merkle reconstruction.

---

## 5. Pre-Flight Verification Before Handover

Before handing off the log package to the SMAOS consulting partner, run the standalone validator:

```bash
smaos-intake-check client_extract.jsonl --expected-rows 25000
```

**Acceptance Criteria for Ingestion:**
* `Row Conservation Status: ✅ PERFECT ZERO-DELTA MATCH`
* `Contract Conservation Δ: 0`
* `Malformed / Corrupted: 0` (or acknowledged in write-off register)
