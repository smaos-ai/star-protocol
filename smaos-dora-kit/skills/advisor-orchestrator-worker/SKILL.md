---
name: advisor-orchestrator-worker
description: Orchestrates complex autonomous agent workflows using the tri-role pattern (Advisor for strategic direction, Orchestrator for task decomposition and gate verification, Worker for leaf execution). Prevents context contamination and guarantees non-recursive convergence.
---

# Advisor-Orchestrator-Worker Skill (OpenClaw Marketplace)

The **Advisor-Orchestrator-Worker (AOW)** pattern establishes clean role boundaries for autonomous swarms operating in high-consequence enterprise environments.

## Role Separation

1. **Advisor (Strategic Counsel)**:
   - Evaluates high-level intent, regulatory boundaries (DORA, GDPR, AI Act), and risk-tier thresholds.
   - Formulates constraints and invariant assertions before any tool use.
   - Does NOT touch local shell or write code directly.

2. **Orchestrator (Execution Governor)**:
   - Translates Advisor constraints into deterministic Depth Trees and task DAGs.
   - Evaluates pre-conditions and post-conditions between worker waves.
   - Verifies evidence against acceptance gates (`GATES.md`) and halts cascades if unexpected status arises.

3. **Worker (Isolated Execution)**:
   - Operates in dedicated, ephemeral worktrees or sandboxes.
   - Strictly executes narrow leaf contracts with bounded file scopes.
   - Yields cryptographic receipts (hashes, test logs, exit codes) back to the Orchestrator.

## Operational Protocol

```text
[Advisor] ──(Invariants & Policy)──> [Orchestrator]
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
               [Worker 1: Rust/Core]                [Worker 2: Reconciler]
                        │                                     │
                        └─────────▶ (Receipts) ◀──────────────┘
                                           │
                                    [Orchestrator]
                                           │
                                 (Gate Verification)
```

## Failure Recovery & Invariants
- If a Worker produces unconfirmed external side effects, the Orchestrator preserves state as `UNKNOWN`.
- Workers never invoke peer workers directly—all peer communication routes through Orchestrator DAG channels.
