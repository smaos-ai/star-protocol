# SMAOS: DORA AI Incident Closure Engine (`smaos-dora-kit`)

[![CI](https://github.com/smaos-ai/star-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/smaos-ai/star-protocol/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Regulatory-Grade](https://img.shields.io/badge/Regulation-EU_2022%2F2554_(DORA)-emerald.svg)](LIMITATIONS.md)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](Cargo.toml)

> **"SMAOS prevents an unconfirmed external effect from being classified as confirmed success within the covered execution boundary. When evidence is incomplete, SMAOS preserves uncertainty as an immutable `UNKNOWN` state, halts dependent risk cascades, and provides mathematically verifiable evidence for human incident response teams."**

---

## 🏛️ Product Positioning: The Evidence Plane for Autonomous Systems

**`smaos-dora-kit`** is a standalone, air-gapped evidence reconstruction and tabletop drill engine engineered to fulfill compliance requirements under **EU Regulation 2022/2554 (Digital Operational Resilience Act &mdash; DORA)** Articles 18, 19, and 24, as well as **Commission Delegated Regulation (EU) 2024/2956**.

When autonomous AI agents initiate mission-critical financial actions (such as high-value SWIFT transfers, credit limit adjustments, or core ledger mutations), network timeouts and dropped telemetry often sever confirmation receipts. Traditional orchestration systems suffer from **Synthetic Success Bias**&mdash;assuming success, retrying blindly, or failing open. 

SMAOS operates as the deterministic **Evidence Plane**: every state transition is anchored to an RFC 8785 Canonical JSON (JCS) and SHA-256 Merkle hash chain. When telemetry fails, SMAOS locks execution into an immutable `UNKNOWN` state, halting dependent risk cascades until authorized dual-control human recovery is completed.

---

## 📐 Architecture: The Four Planes

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        SMAOS FOUR-PLANE SYSTEM ARCHITECTURE                            │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. EVIDENCE PLANE (`journal.rs`, `timeline.rs`)                                        │
│    • RFC 8785 Canonical JSON (JCS) serialization for deterministic hashing.            │
│    • SHA-256 Merkle hash-chaining: H_n = SHA256(action_id || seq || JCS(s) || H_prev).│
│    • Strict zero-`unwrap()` safety policy mapping errors to typed JournalError enums.   │
│    • Multi-clock T0–T9 mapper: timestamps default to Option<u64> to render gaps.       │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. ASSURANCE PLANE (`clock.rs`, `threshold.rs`, `exposure.rs`)                         │
│    • Human-gated DORA Art. 19 deadline engine (locks in CLASSIFICATION_PENDING).       │
│    • DORA Art. 18 / RTS 2024/2956 major incident classification threshold evaluator.   │
│    • Cost-of-Uncertainty ledger: tracks trapped capital and >900s escalation alerts.   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 3. ANALYSIS PLANE (`protocol_drift.rs`, `config_lineage.rs`, `smaos_audit`)           │
│    • Shannon entropy & Out-Of-Vocabulary (OOV) emergent jargon anomaly detector.       │
│    • Change Lineage Graph: tracks before/after digests and authorization permits.       │
│    • Read-only environment inspection CLI calculating Governance Intensity Index (GII).│
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 4. ACTION PLANE (Explicitly Disabled in v1 Open-Source "Door 1")                       │
│    • Active production mutation, automated rollbacks, and closed reconcilers are        │
│      quarantined to the enterprise gateway sidecar ("Door 2").                         │
│    • Door 1 is 100% read-only, non-egress, and air-gap verified.                      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quickstart & CLI

### Prerequisites
* **Rust 1.80+** (`cargo --version`)
* Modern web browser (for the standalone HTML Black Box)

### 1. Build and Run Tests
```bash
cargo test
cargo clippy --all-targets -- -D warnings -D clippy::unwrap_used
```

### 2. Run the Read-Only Audit CLI Scanner
Audit local developer agent configuration vectors, verify Git commit provenance, and compute your **Governance Intensity Index (GII)**:

```bash
cargo run --bin smaos_audit
```
*Sample output:*
```text
================================================================================
🛡️  SMAOS GHOST AUDIT CLI (v1.0.5) — DORA AI Governance Intensity Inspector
================================================================================
Target Framework:  EU Regulation 2022/2554 (DORA) Articles 18, 19, & 24
Execution Mode:    READ-ONLY • ZERO NETWORK EGRESS • DETERMINISTIC
================================================================================

🔍 1. Scanning Developer Agent Configuration Vectors...
   [FOUND] Config vector: ~/.claude/settings.json
   [FOUND] Config vector: .env.production
   [FOUND] Config vector: smaos.hcl

🔍 2. Auditing Git Lineage & Evidence Continuity...
   [PASS] Git repository initialized (.git present)
   [PASS] Commit provenance: Verified against local tree reflog

🔍 3. Verifying Canonical Ghost Incident (ACT-SWIFT-9901)...
   [PASS] Merkle Hash-Chain: 10/10 events verified bit-exact
   [PASS] Root Digest: 75a5804818759220202c629ee94e964d4f7e6507472f6950365679939c465422

================================================================================
📊 GOVERNANCE INTENSITY INDEX (GII): 94.5 / 100
================================================================================
• Status:                 PRODUCTION AUDIT GRADE
• Uncertainty Control:    IMMUTABLE UNKNOWN PRESERVATION ACTIVE
• Safe Mode Protection:   LEVEL 2 DEPENDENCY HALT ARMED
• Dual-Control Recovery:  TWO-PERSON RULE ENFORCED (Op1 != Op2)
• Air-Gap Guarantee:      100% OFFLINE (0 BYTES EGRESSED)
================================================================================
```

### 3. Launch the Air-Gapped Tabletop Black Box
The kit includes a zero-dependency, standalone HTML application for conducting DORA Article 24 tabletop drills:

```bash
open dist/dora_tabletop_kit.html
```

* **Client-Side WebCrypto Verifier:** Recomputes the SHA-256 Merkle hash chain in `< 0.22ms` directly inside browser memory.
* **T0–T9 Forensic Timeline Stepper:** Step through Proposed $\rightarrow$ Authorized $\rightarrow$ Dispatched $\rightarrow$ Reconciliation Timeout $\rightarrow$ `UNKNOWN` Lock $\rightarrow$ Level 2 Safe Mode $\rightarrow$ Dual-Control Recovery.
* **Live Article 19 Statutory Clocks:** Tracks the 24h awareness window, 4h initial notification, 72h intermediate update, and 30d final report.
* **Live Tamper Injection Banner:** Real-time demonstration of cryptographic hash-chain collapse upon payload mutation.
* **Zero Remote Assets:** No external CDNs, fonts, or scripts. 100% air-gap safe.

---

## ⚖️ Claims Discipline Matrix

To preserve absolute regulatory credibility, all technical claims adhere to strict semantic boundaries:

| What SMAOS Says | What SMAOS Never Says |
| :--- | :--- |
| "SMAOS preserved the unconfirmed external ledger effect as an immutable `UNKNOWN` state." | *"SMAOS guaranteed the SWIFT transaction succeeded."* |
| "SMAOS cryptographically verifies the monotonic sequence and Merkle continuity of supplied event logs." | *"SMAOS proves the internal state and solvency of the external core banking system."* |
| "SMAOS enforces dual-control human authorization prior to unlocking dependent workflows." | *"SMAOS autonomously resolves financial settlement discrepancies."* |
| "SMAOS provides structured evidence and statutory countdown timers to assist human incident managers under DORA Article 19." | *"SMAOS automatically submits and legally certifies DORA major incident reports."* |
| "SMAOS provides standardized incident drill packages pursuant to DORA Article 24 tabletop requirements." | *"SMAOS replaces Threat-Led Penetration Testing (TLPT) under DORA Article 26."* |

---

## 📜 Legal Limitations & Statutory Boundaries

SMAOS is a read-only evidence reconstruction and uncertainty-accounting engine. It does not replace executive accountability, legal counsel, or competent authority reporting.

Read the complete [1-Page Board & Legal Memorandum](LIMITATIONS.md) for statutory boundaries under EU 2022/2554 and RTS 2024/2956.

---

## 🔒 Security & Air-Gap Model

* **Zero-Socket Architecture:** The core library contains zero network sockets, zero HTTP clients, and zero telemetry collection.
* **Deterministic Execution:** No reliance on non-deterministic external time without explicit uncertainty windows.
* Read [SECURITY.md](SECURITY.md) for threat modeling and vulnerability reporting procedures.

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
