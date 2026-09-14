# SMAOS Statutory Limitations & Regulatory Boundary Declaration

**Document Type:** 1-Page Board & Legal Memorandum  
**Statutory Reference:** EU Regulation 2022/2554 (DORA) &bull; Commission Delegated Regulation (EU) 2024/2956  
**Audience:** Chief Information Security Officers (CISO), Chief Risk Officers (CRO), Heads of Internal Audit, Supervisory Examiners (EBA, ESMA, EIOPA, National Competent Authorities)

---

## 1. Statutory Role & Demarcation

`smaos-dora-kit` operates strictly as a **read-only forensic evidence reconstruction and uncertainty-accounting engine**. It is engineered to assist financial entities in fulfilling their digital operational resilience obligations under DORA Chapter II (ICT Risk Management, Arts. 18–19) and Chapter IV (Digital Operational Resilience Testing, Art. 24).

### What SMAOS Does:
1. **Evidence Integrity Verification:** Reconstructs and cryptographically verifies the integrity and monotonic sequence of incident evidence supplied to it using RFC 8785 Canonical JSON (JCS) and SHA-256 Merkle hash-chaining.
2. **Uncertainty Preservation:** Prevents synthetic success assumptions by locking actions into an immutable `UNKNOWN` state whenever downstream external ledger confirmations are missing, conflicting, or timed out.
3. **Tabletop Drill Rehearsal:** Provides standardized tabletop drill packages and multi-clock timeline reconstruction to evaluate human incident-response procedures pursuant to DORA Article 24.
4. **Regulatory Timer Tracking:** Tracks DORA Article 19 statutory reporting deadlines (24h awareness window, 4h post-classification initial notification, 72h intermediate update, 30d final report).

---

## 2. Four Non-Negotiable Boundaries

To prevent regulatory misinterpretation, the following operational and statutory boundaries are legally binding across all deployments:

1. **No Auto-Classification (`CLASSIFICATION_PENDING`):**  
   SMAOS does **NOT** automatically submit, report, or legally classify an incident as a "DORA Major Incident." The statutory classification obligation under Article 19(1) and RTS 2024/2956 rests exclusively with the authorized human officers of the financial entity. All regulatory countdown clocks remain in `CLASSIFICATION_PENDING` until explicit human sign-off is recorded.
2. **No Proof of External Truth:**  
   SMAOS verifies that a receipt or confirmation was or was not delivered within the observed execution boundary. It does **NOT** audit, prove, or guarantee the internal solvency, truthfulness, or soundness of third-party core banking systems, SWIFT networks, or external settlement venues.
3. **No Blanket Compliance or TLPT Replacement:**  
   Execution of SMAOS does **NOT** automatically confer statutory compliance with DORA, NIS2, or the EU AI Act. Furthermore, tabletop simulation drills conducted with this kit do **NOT** substitute for Threat-Led Penetration Testing (TLPT) mandates required under DORA Article 26.
4. **Covered Boundary Only:**  
   SMAOS governs only actions, workflows, and agents routed through its registered assurance adapters. It does not intercept, monitor, or protect transactions executed outside its declared execution perimeter.

---

## 3. Mandatory Examiner Communication Guardrails

When presenting audit evidence, tabletop results, or incident timelines to internal audit committees or supervisory examiners, personnel must adhere strictly to these communication guardrails:

| DO STATE | DO NOT STATE |
| :--- | :--- |
| *"SMAOS preserved the uncertainty of the unconfirmed SWIFT message as an immutable UNKNOWN state and halted dependent credit disbursements."* | *"SMAOS proved the external payment succeeded and guaranteed our institution complies with DORA Article 19."* |
| *"SMAOS cryptographically proved the monotonic event sequence and tamper-free state of our local incident evidence."* | *"SMAOS certified our third-party core banking provider's ledger as accurate."* |
| *"SMAOS tracked statutory Article 19 countdown windows following formal incident classification by the Chief Risk Officer."* | *"SMAOS autonomously submitted our initial major incident notification to the European Banking Authority."* |
| *"SMAOS served as a standardized tabletop simulation artifact for our DORA Article 24 testing program."* | *"SMAOS exempted our institution from conducting required Threat-Led Penetration Testing (TLPT)."* |
