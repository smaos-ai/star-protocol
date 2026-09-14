# Security Policy & Air-Gap Non-Egress Guarantees

## 1. Security Architecture & Threat Model

`smaos-dora-kit` is engineered for air-gapped, zero-trust financial environments. The primary objective is ensuring that evidence reconstruction, timeline analysis, and tabletop drills execute **completely offline** without leaking sensitive banking payloads or credentials.

### Threat Assumptions & Guarantees
1. **Zero Outbound Telemetry (Air-Gap Invariant):**
   - The engine contains zero network sockets, zero tracking analytics, zero remote telemetry endpoints, and zero external font or script imports.
   - All cryptographic proofs (SHA-256 Merkle chain, JCS canonicalization) execute locally in-memory or within client-side WebCrypto / WebAssembly environments.

2. **Tamper-Evident Hash Chaining:**
   - Every journal event is cryptographically bound to the previous event via:
     $$\text{event\_hash} = \text{SHA256}(\text{action\_id} \mathbin{\Vert} \text{sequence} \mathbin{\Vert} \text{JCS}(\text{payload}) \mathbin{\Vert} \text{prev\_hash})$$
   - Any modification, deletion, reordering, or parameter forgery breaks the Merkle chain, immediately triggering alert banners.

3. **Memory Safety & Panic Freedom:**
   - Strict zero-`unwrap()` policy in production code.
   - All I/O, parsing, and cryptographic operations return explicit `Result<T, JournalError>` types.

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability or evidence serialization flaw in `smaos-dora-kit`:
- **Do NOT open a public GitHub issue.**
- Email security findings to: `security@sovereignnexus.io` with GPG encryption.
- Include reproduction steps, sample event payloads, and expected vs. actual hash outputs.
