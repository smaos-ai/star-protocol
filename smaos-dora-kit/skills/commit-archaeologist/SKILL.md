---
name: commit-archaeologist
description: Forensic Git history and AST mutation investigator. Traces commit lineages, recovers lost worktree revisions, audits cryptographic commit signatures, and identifies regression inflection points across large repositories.
---

# Commit Archaeologist Skill (OpenClaw Marketplace)

The **Commit Archaeologist** provides deterministic inspection of git histories, tree graphs, and reflogs to establish forensic lineage and recover lost work.

## Core Capabilities

1. **Reflog & Dangling Tree Recovery**:
   - Searches dangling commits and orphaned branch heads across `.git/logs/` and worktrees.
   - Extracts patches and cherry-picks changes without destructive rebasing.

2. **Semantic Bisection & Invariant Tracing**:
   - Identifies the exact commit where a cryptographic invariant or AST structural drift was introduced.
   - Cross-references AST Golden Baseline hashes with historical tree objects.

3. **Regulatory Provenance Auditing**:
   - Verifies Ed25519 commit signatures against `.allowed_signers` for DORA Chapter V compliance.
   - Extracts author, committer, and co-author cryptographic receipts for third-party examiner reviews.

## Standard Commands

```bash
# Locate unreachable heads and dangling commits
git fsck --lost-found

# Trace symbol mutation across commit boundaries
git log -S "symbolName" --patch --stat

# Verify GPG/SSH signatures across release range
git log --show-signature -n 20
```
