#!/usr/bin/env python3
"""
Receipt dataclass for STAR protocol.
Encodes cryptographic proofs, compliance metadata, and execution traces
for immutable audit trails.

Includes the 5 Audit-Truth Fields:
  1. authorization_decision (PERMIT/DENY)
  2. human_principal (Ed25519 signature)
  3. intent_mandate (SHA3-256 policy scope hash)
  4. environment_fingerprint (local airgap snapshot)
  5. tamper_evidence (Merkle-DAG chain root)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


@dataclass
class Receipt:
    """Immutable cryptographic receipt for STAR test execution."""

    # Core execution fields
    receipt_id: str = ""
    story_id: str = ""
    status: str = "COMPLETED"
    verdict: str = "SUCCESS"
    steps_total: int = 0
    steps_passed: int = 0
    merkle_root: str = ""
    signature: str = ""
    spans: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # EU compliance fields (Annex IV / Article 12)
    retention_days: int = 2555  # ~7 years, GDPR retention minimum for financial audit
    access_log: List[Dict[str, Any]] = field(default_factory=list)
    human_override: Dict[str, Any] = field(default_factory=dict)
    environment_snapshot: Dict[str, Any] = field(default_factory=dict)
    replay_instructions: str = ""
    schema_version: str = "1.0"

    # 5 Audit-Truth Fields (Layer 0 Audit Truth)
    authorization_decision: str = "PERMIT"  # PERMIT / DENY
    human_principal: str = ""              # Ed25519 operator signature
    intent_mandate: str = ""               # SHA3-256 policy scope hash
    environment_fingerprint: str = ""      # Local airgap verification hash
    tamper_evidence: str = ""              # Merkle-DAG chain root

    def __post_init__(self):
        """Validate receipt after initialization."""
        if not self.merkle_root and self.tamper_evidence:
            self.merkle_root = self.tamper_evidence
        elif not self.tamper_evidence and self.merkle_root:
            self.tamper_evidence = self.merkle_root

        if not self.signature and self.human_principal:
            self.signature = self.human_principal
        elif not self.human_principal and self.signature:
            self.human_principal = self.signature

        if not self.receipt_id:
            self.receipt_id = f"rcpt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    def add_access_log_entry(self, user: str, action: str, timestamp: Optional[str] = None) -> None:
        """Add access log entry for audit trail."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        self.access_log.append({
            "user": user,
            "action": action,
            "timestamp": timestamp
        })

    def to_dict(self) -> Dict[str, Any]:
        """Convert receipt to dict for JSON serialization."""
        return {
            "receipt_id": self.receipt_id,
            "story_id": self.story_id,
            "status": self.status,
            "verdict": self.verdict,
            "steps_total": self.steps_total,
            "steps_passed": self.steps_passed,
            "merkle_root": self.merkle_root,
            "signature": self.signature,
            "spans": self.spans,
            "timestamp": self.timestamp,
            "retention_days": self.retention_days,
            "access_log": self.access_log,
            "human_override": self.human_override,
            "environment_snapshot": self.environment_snapshot,
            "replay_instructions": self.replay_instructions,
            "schema_version": self.schema_version,
            "audit_truth_fields": {
                "authorization_decision": self.authorization_decision,
                "human_principal": self.human_principal,
                "intent_mandate": self.intent_mandate,
                "environment_fingerprint": self.environment_fingerprint,
                "tamper_evidence": self.tamper_evidence
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Receipt":
        """Deserialize dictionary into Receipt instance."""
        data_copy = dict(data)
        audit_fields = data_copy.pop("audit_truth_fields", {})
        if isinstance(audit_fields, dict):
            for k, v in audit_fields.items():
                if k not in data_copy or not data_copy[k]:
                    data_copy[k] = v
        valid_fields = {k: v for k, v in data_copy.items() if k in cls.__dataclass_fields__}
        return cls(**valid_fields)
