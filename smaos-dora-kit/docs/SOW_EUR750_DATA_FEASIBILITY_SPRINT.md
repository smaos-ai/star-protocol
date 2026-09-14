# Statement of Work: €750 Data Feasibility Sprint
**Contract Reference:** `SOW-SMAOS-FEASIBILITY-EUR750-v1.0`  
**Fixed Fee:** €750.00 EUR (Net of applicable taxes) &bull; **Turn-around SLA:** 48 Hours  
**Payment Terms:** 100% upon signing / Corporate Procurement Card / Short-Form PO  
**Execution Paradigm:** 100% Air-Gapped / Zero Network Egress / On-Premise Execution

---

## 1. Objective & Fast-Track Engagement Scope
This rapid-validation sprint evaluates the feasibility and data coverage of the Client's autonomous agent execution logs using the **SMAOS Local Review Engine (`smaos-review`)**.

Within **48 hours** of receiving up to **250 customer-sanitized log records**, SMAOS delivers a complete 8-file cryptographic audit package proving zero-delta row conservation, isolating unconfirmed agent actions, and pre-filling DORA Article 18/19 reporting templates.

---

## 2. In-Scope Deliverables (The 8-File `review/` Bundle)

The Provider delivers the co-branded audit package in `out/review/`:

1. **`conservation_scorecard.json`**: Mathematical proof of 100% row conservation ($\Delta = 0$) across the 250 declared records.
2. **`unknown_exposure_inventory.json`**: Action vs. observation gap catalog of all transactions locked in `UNKNOWN` state due to downstream timeouts.
3. **`criteria_matrix.json`**: Evaluation against DORA Article 18 and EU 2024/1772 major incident thresholds, with statutory clocks under RTS 2025/301 Art. 4(2).
4. **`replay.json`**: Counterfactual blast-radius replay contrasting baseline exposure with modeled policy holds.
5. **`kpi_baseline.json`**: Pilot efficiency audit quantifying reconstruction duration and analyst effort savings.
6. **`servicenow_case_export.json`**: Draft ServiceNow IRM payload (`sn_si_incident`) with `human_approval_required_before_push: true`.
7. **`evidence_manifest.json`**: JCS Merkle root digest, Ed25519 signature, and PostSignum RFC 3161 timestamp token.
8. **`LIMITATIONS.md`**: 1-Page board and legal memorandum defining source coverage boundaries.

---

## 3. Data Intake Requirements
The Client provides a sanitized `.jsonl` extract conforming to the [1-Page Client Data Intake Specification](CLIENT_DATA_INTAKE_SPECIFICATION.md):
* **Row Count:** Up to 250 records.
* **Sanitization:** Account identifiers (IBANs) and counterparty names masked locally prior to handover.
* **Pre-Flight Validation:** Verified locally using `smaos-intake-check` prior to transmission.

---

## 4. Path to Production & Pilot Credit
The entire **€750 fee is 100% credited** against the fixed price of the full **5-Day Unknown Exposure Review (€5,000 intro wholesale)** or **10-Day Production Tabletop Pilot (€15,000)** upon signature within 30 days of deliverable handover.

---

## 5. Execution Sign-Off

**For the Client:**  
Name: _______________________________  
Title: _______________________________  
Date: _______________________________  

**For SMAOS Resilience Engineering:**  
Name: _______________________________  
Title: _______________________________  
Date: _______________________________  
