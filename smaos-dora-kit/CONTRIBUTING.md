# Contributing to SMAOS DORA Kit

We welcome contributions to the open-source SMAOS DORA Kit. To maintain regulatory-grade auditability and deterministic verification, all contributions must adhere to these guidelines.

---

## 🛡️ Non-Negotiable Engineering Invariants

1. **Zero `unwrap()` Policy:**
   - Production code (`src/**/*.rs`) must never call `.unwrap()`, `.expect()`, or `panic!()`.
   - All errors must map to typed `JournalError` variants.
   - Run `cargo clippy -- -D clippy::unwrap_used` prior to opening a PR.

2. **RFC 8785 JCS Determinism:**
   - Any modification to serialized structures must maintain lexicographical key sorting and canonical JSON formatting without whitespace.
   - SHA-256 event digests must match bit-exact across Rust, Python, and WebCrypto implementations.

3. **Multi-Clock Invariant:**
   - Timestamps must never default to `0`. Missing external receipts must be explicitly typed as `None` (`Option<u64>`), rendering as visible evidence gaps.

4. **Offline Compilation Viability:**
   - The crate must compile in strict offline mode (`cargo test --offline`).
   - No external network-dependent dependencies may be introduced.

---

## 🧪 PR Verification Checklist

Before submitting a pull request:
```bash
# 1. Run unit test suite
cargo test --offline

# 2. Check for zero unwrap / clippy lints
cargo clippy --all-targets -- -D warnings

# 3. Verify CLI execution
cargo run --bin smaos_audit
```
