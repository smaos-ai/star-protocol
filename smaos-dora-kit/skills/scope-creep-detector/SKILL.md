---
name: scope-creep-detector
description: Prevents unapproved architectural drift, file sprawl, unnecessary refactoring, and AST Golden Baseline degradation during autonomous implementation sprints.
---

# Scope Creep Detector Skill (OpenClaw Marketplace)

The **Scope Creep Detector** continuously monitors autonomous agent workspaces to ensure modifications strictly match the approved sprint backlog and specification.

## Core Invariants

1. **AST Golden Baseline Preservation**:
   - Forbids incidental changes to protected core directories (`smaos/`, `star_protocol/`, `scripts/`, `crates/`).
   - Re-verifies AST node count (2,522 / 2,522) and Merkle root before every commit.

2. **Diff Radius Monitoring**:
   - Flags files modified outside the declared `OWNS:` leaf boundary.
   - Rejects extraneous formatting refactors, unsolicited dependency additions, or cosmetic renaming.

3. **Spec Alignment Checks**:
   - Asserts that every modified function or newly introduced module maps 1:1 to an explicit user story or acceptance gate.
   - Enforces fail-closed rejection on out-of-scope feature creep.

## Verification Checklist

```bash
# Verify git status touch radius against declared scope
git status --short

# Run AST verification gate to ensure 0.00% drift
python3 scripts/star_legacy_verify.py
```
