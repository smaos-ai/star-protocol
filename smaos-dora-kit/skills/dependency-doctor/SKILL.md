---
name: dependency-doctor
description: Diagnoses and remediates package dependency graphs, license incompatibilities, offline cargo caching failures, circular imports, and supply-chain vulnerabilities under DORA Article 28/30 ICT fourth-party concentration rules.
---

# Dependency Doctor Skill (OpenClaw Marketplace)

The **Dependency Doctor** inspects and hardens dependency graphs across polyglot ecosystems (Rust Cargo, Python pip/uv, Node.js npm).

## Core Capabilities

1. **Air-Gapped & Offline Cache Validation**:
   - Ensures all crates and packages compile in strict offline mode (`--offline`).
   - Identifies vendored vs. external remote dependencies to eliminate hidden internet egress.

2. **DORA Fourth-Party Risk Auditing (Article 30)**:
   - Maps deep dependency trees to identify critical third-party and fourth-party components.
   - Flags unmaintained crates, untrusted sub-processors, or transitive vulnerabilities.

3. **Lockfile & Hash Integrity Verification**:
   - Validates checksums in `Cargo.lock`, `package-lock.json`, and `uv.lock`.
   - Generates CycloneDX / SPDX Software Bill of Materials (SBOM) for regulatory submission.

## Diagnostic Protocol

```bash
# Check for offline compile viability in Rust
cargo check --offline

# Inspect outdated or vulnerable dependencies
cargo audit

# Trace why a specific dependency is pulled into the graph
cargo tree -i <crate-name>
```
