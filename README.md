# STAR Protocol (`star-protocol`)
> **Story-Trace-Assert-Receipt (STAR)** — Local, zero-cost verification harness and AST Merkle DAG receipt generator for autonomous agent execution.

---

## ⚡ The Core Problem: Agent Claim ≠ Downstream Observation ≠ Confirmed Effect

Traditional logging tracks what an agent *attempted* or what an API returned (`200 OK`). It does not prove whether the downstream effect actually occurred.

- **Token Explosions & Compaction Cliff:** Multi-turn sessions re-read context, token cost scales, security rules decay as context compacts.
- **Silent Failures (Swallow Loops):** HTTP 504, partial tool failures, while console shows green checkmarks.
- **Unconfirmed Retries:** Retrying UNKNOWN actions without lineage creates duplicate payments / writes.
- **Cloud Exfiltration Risk:** Uploading logs + code to SaaS dashboards raises data residency and audit-trail risk touching **EU AI Act Art. 12 (logging), Art. 14 (human oversight)** and **DORA Art. 28 (ICT third-party risk)**.

> **STAR closes the gap.** When confirmation is missing, STAR preserves `UNKNOWN` rather than assuming success, enforces Δ=0 conservation, and outputs a human-reviewable evidence package, 100% locally.

---

## 📊 30-Second Check — Do You Need STAR?

| Problem you see | Why it hurts | STAR fix |
| :--- | :--- | :--- |
| 💸 Tokens exploding | You pay for full context re-reads | Local AST, **$0 API**, -70-85% context *locally measured* |
| 👻 Timeouts showing as Success | Silent drift, money at risk | **Δ=0**, every row = confirmed / unknown / conflict-held / malformed |
| ☁️ Logs sent to SaaS | IP leak + residency risk | **100% local**, 0-byte egress by design |
| 🧠 Safety rules fading | Compaction cliff | Ed25519 Merkle freeze + drift detection |

---

## 🎯 Quick Wins (Who Benefits?)

- **Engineering Leads & Developers:** Freeze golden baselines, catch hallucinated passes before merge, sub-second local check, $0 API cost.
- **Incident Response & GRC Consultants:** Audit broken multi-agent runs, deliver zero-delta scorecards in under 5 minutes.
- **CISOs & Risk Officers:** 100% air-gapped, 0-byte egress by design, Ed25519-signed receipts to support your DORA / EU AI Act workflow, does not determine legal classification.

---

## 💰 Token Economics

- **70–85% context reduction:** Tree-sitter AST + Bloom filter isolates blast radius, re-runs only affected logic. *Local measurements on commodity hardware.*
- **$0 API verification cost:** Baseline + Merkle generation runs locally.
- **Stops flailing:** Server-authoritative gate stops retry loops.

---

## 📈 Reality Math & Conservation Invariant

STAR enforces strict **Zero-Delta Conservation:**

```
input_rows == confirmed + unknown + conflict_held + malformed
Delta = 0
```

Every row gets exactly one primary disposition, no drops, no double-counts.

- **confirmed:** executed and externally verified
- **unknown:** timeout / missing downstream confirmation (e.g., HTTP 504)
- **conflict-held:** retry collision / state race, held for human review
- **malformed:** invalid payload / schema

| Metric | Reality | Impact |
| :--- | :--- | :--- |
| Verification Speed | ~0.4s / exec local | Sub-second DAG check |
| Token Savings | 70–85% reduction local | Prevents re-reads |
| Cloud Egress | 0 Bytes by design | Air-gapped |
| Accounting | Δ=0 | 100% row reconciliation |
| Retention | 7-year capable | Signed JCS SHA-256 + Ed25519 receipts in local SQLite/JSON |

---

## 🛠 How It Works: 3-Step Local Pipeline

```text
[ Raw Agent Logs / PRs ] → 1. PARSE (Tree-sitter AST) → 2. PROVE (JCS SHA-256 Merkle + Ed25519) → 3. GATE (confirmed | unknown | conflict-held | malformed) → [ review/ 8-file bundle ]
```

---

## 📦 Audit Deliverable Package (`review/`) — 8 Files

1. `conservation_scorecard.json` — Δ=0 accounting + secondary findings map
2. `unknown_exposure_inventory.json` — UNKNOWN timeouts & retry conflicts
3. `telemetry_gaps.json` — schema gaps + degraded confidence flags
4. `evidence_insufficient_or_findings.json` — 3-outcome verdict: FINDINGS / NO FINDINGS / INSUFFICIENT
5. `replay.json` — T0–T9 forensic replay fixture
6. `limitations.md` — human-in-the-loop boundaries
7. `processing_and_deletion_record.json` — local shredding audit trail (not a Certificate of Deletion)
8. `manifest.json` — JCS SHA-256 Merkle root, file digests, commit hash

---

## 💼 Commercial Feasibility Sprint

> **For €750, SMAOS reviews up to 250 customer-approved or synthetic records from one workflow and returns a conservation scorecard, unknown-effect analysis, telemetry-gap report, or evidence-insufficiency report within 48 hours. The fee is credited toward a €3,500 forensic review signed within 60 days.**

> **SMAOS does not determine legal classification, submit regulatory reports, prove external-system truth, or establish that source data was complete before ingestion.**

Scope: 250 rows JSONL. No ServiceNow export in €750 package, kept for €3,500 sprint or separate connector.

---

## ⚠ Scope & Limitations

STAR is an evidence-reconstruction and verification artifact. Human-in-the-loop remains authoritative. No production deployment, no automatic regulatory submission, no DORA-compliant marketing claims, no 100% anonymized claims, no unverified stats.

---

## 📜 License

Licensed under the [Apache License, Version 2.0](LICENSE).
