# STAR Protocol Statutory Limitations & Regulatory Boundary Declaration

**Document Type:** 1-Page Human-in-the-Loop & Statutory Demarcation Memorandum  
**Statutory Anchors:** EU AI Act (Regulation 2024/1689) Arts. 12 & 14 • DORA (Regulation 2022/2554) Arts. 18, 19 & 28  
**Package:** €750 Data Feasibility Sprint (Up to 250 records)  

---

## 1. Statutory Role & Demarcation
STAR Protocol (`star-protocol`) and SMAOS operate strictly as a **read-only forensic evidence reconstruction and uncertainty-accounting engine**. It parses supplied agent logs, detects downstream telemetry gaps, and locks unconfirmed actions into immutable `UNKNOWN` states.

### What STAR Does:
1. **Zero-Delta Conservation:** Enforces `input_rows == confirmed + unknown + conflict_held + malformed` ($\Delta = 0$).
2. **Uncertainty Preservation:** Preserves `UNKNOWN` whenever downstream confirmation is timed out or absent.
3. **Cryptographic Integrity:** Generates offline JCS SHA-256 Merkle DAG receipts signed with Ed25519.

---

## 2. Four Non-Negotiable Human-in-the-Loop Boundaries
1. **Pre-Ingestion Completeness Unproven:** STAR audits only the records extracted and declared in the source contract. It does not prove that source systems logged all relevant events prior to extraction.
2. **No Automated Regulatory Classification:** Human risk officers and incident managers remain strictly authoritative under EU AI Act Art. 14 and DORA Art. 18. STAR does not submit filings to NCAs or make autonomous legal classifications.
3. **No Proof of External-System Truth:** A confirmed receipt proves local transmission and telemetry reception; it does not guarantee the solvency or internal consistency of external bank ledgers.
4. **Local Verification Artifact:** This feasibility sprint package is a technical verification deliverable. It does not constitute a formal Threat-Led Penetration Testing (TLPT) certification or regulatory signoff.
