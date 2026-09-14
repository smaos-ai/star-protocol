# Statement of Work: 5-Day Unknown Exposure Review
**Contract Code:** `SOW-SMAOS-5DAY-WHOLESALE-v1.0` &bull; **Standard Pricing:** €10,000 &bull; **Introductory Wholesale:** €5,000  
**Payment Structure:** 50% upon contract execution / 50% upon delivery of the 5-Deliverable Package  
**Execution Mode:** 100% Offline / Air-Gapped CLI Execution (`smaos-review`)

---

## 1. Engagement Overview
This fixed-price Statement of Work governs the execution of a **5-Day Unknown Exposure Review** conducted by the Consulting Partner using the **SMAOS Local Review Engine (`smaos-review`)**.

The engagement identifies unconfirmed external agent effects, isolates downstream gateway timeouts (`HTTP 504`), calculates historical vs. modeled exposure replay under policy holds, and formats an audit-ready DORA major incident case package.

---

## 2. Five-Day Delivery Schedule

```text
┌──────────────┬────────────────────────────────────────────────────────────────────────┐
│ Day 1: Setup │ Sign Source Extraction Contract (CONN-SN-CZ-001) and receive 24–72h    │
│              │ client sanitized execution logs (up to 250,000 JSONL records).         │
├──────────────┼────────────────────────────────────────────────────────────────────────┤
│ Day 2: Intake│ Run `smaos-intake-check` to verify row conservation and zero delta.   │
│              │ Ingest logs into local `smaos-review` engine in air-gapped mode.       │
├──────────────┼────────────────────────────────────────────────────────────────────────┤
│ Day 3: Audit │ Quantify unconfirmed UNKNOWN transactions, duplicate nonces, and gross │
│              │ nominal exposure (€380,000 demonstration baseline).                    │
├──────────────┼────────────────────────────────────────────────────────────────────────┤
│ Day 4: Replay│ Execute counterfactual blast-radius replay; evaluate DORA Art. 18 /   │
│              │ EU 2024/1772 criteria and Delegated Regulation 2025/301 Art. 4(2).     │
├──────────────┼────────────────────────────────────────────────────────────────────────┤
│ Day 5: Final │ Export ServiceNow draft case payload (`sn_si_incident`) and deliver    │
│              │ the complete 5-Deliverable Pilot Pack to the client CISO / CRO.        │
└──────────────┴────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The 5 Core Client Deliverables (`out/review/`)

Upon completion, the Client receives the full cryptographic audit bundle:

1. **Unknown Exposure Inventory (`unknown_exposure_inventory.json`):**  
   Exhaustive registry of all agent transactions locked in `UNKNOWN` state due to downstream timeouts.
2. **Source Coverage Scorecard (`conservation_scorecard.json`):**  
   Mathematical proof of zero-delta row conservation across all declared extraction rows.
3. **Counterfactual Replay Analysis (`replay.json`):**  
   Side-by-side blast-radius comparison of baseline historical uncontained exposure vs. modeled policy holds (€0 uncontained), with required legal disclaimers.
4. **DORA Criteria Evidence Matrix (`criteria_matrix.json`):**  
   Article 18 threshold analysis, statutory clock deadlines under RTS 2025/301 Art. 4(2), and Direct Loss Partition (EU 2024/1772 Art. 8).
5. **ServiceNow Draft Case Export (`servicenow_case_export.json`):**  
   Draft `sn_si_incident` case payload with pre-filled Annex I templates and `human_approval_required_before_push: true`.

---

## 4. Statutory & Boundary Disclaimers
1. **No Proof of Source Completeness:** The review evaluates only records declared in the Source Contract; pre-ingestion source completeness is not independently certified.
2. **Human Prerogative:** The engine does not submit regulatory filings automatically. DORA classification remains the exclusive legal responsibility of the Client’s authorized officers.
3. **No TLPT Replacement:** This historical log review does not replace Threat-Led Penetration Testing mandates under DORA Article 26.
