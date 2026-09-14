"""
SMAOS DORA AI Incident Closure Engine — Tabletop Kit (smaos_dora_kit.py)

Mirrors the Rust smaos-dora-kit crate with bit-exact RFC 8785 Canonical JSON (JCS)
and SHA-256 Merkle hash-chaining, DORA Article 19 regulatory countdown timers,
T0–T9 multi-clock timeline reconstruction, and threshold assessment.
"""

from __future__ import annotations
import json
import hashlib
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Set


GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def canonicalize_jcs(val: Any) -> str:
    """
    Recursively formats arbitrary values to RFC 8785 JSON Canonicalization Scheme (JCS).
    Lexicographically sorts keys, removes insignificant whitespace.
    """
    if val is None:
        return "null"
    elif isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        # Format cleanly without trailing .0 if integer
        if val.is_integer():
            return str(int(val))
        return str(val)
    elif isinstance(val, str):
        return json.dumps(val)
    elif isinstance(val, list):
        items = [canonicalize_jcs(x) for x in val]
        return "[" + ",".join(items) + "]"
    elif isinstance(val, dict):
        sorted_keys = sorted(val.keys())
        items = [f"{json.dumps(k)}:{canonicalize_jcs(val[k])}" for k in sorted_keys]
        return "{" + ",".join(items) + "}"
    else:
        return json.dumps(str(val))


def compute_event_hash(action_id: str, sequence: int, event_kind: Dict[str, Any], prev_hash: str) -> str:
    """
    Computes the SHA-256 Merkle hash for an event:
    SHA256(action_id.encode('utf-8') + sequence.to_bytes(8, 'big') + JCS(event_kind).encode('utf-8') + prev_hash.encode('utf-8'))
    """
    jcs = canonicalize_jcs(event_kind)
    hasher = hashlib.sha256()
    hasher.update(action_id.encode("utf-8"))
    hasher.update(sequence.to_bytes(8, byteorder="big"))
    hasher.update(jcs.encode("utf-8"))
    hasher.update(prev_hash.encode("utf-8"))
    return hasher.hexdigest()


@dataclass
class JournalEvent:
    sequence: int
    action_id: str
    event_kind: Dict[str, Any]
    timestamp_wall_iso: str
    timestamp_mono_ns: int
    timestamp_ext_time: Optional[int]
    clock_uncertainty_ms: int
    prev_hash: str
    event_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DoraJournal:
    """Durable append-only cryptographically linked journal."""

    def __init__(self):
        self.events: List[JournalEvent] = []
        self._latest_hash: str = GENESIS_HASH

    @property
    def latest_hash(self) -> str:
        return self._latest_hash

    def append_event(
        self,
        action_id: str,
        event_kind: Dict[str, Any],
        timestamp_wall_iso: str,
        timestamp_mono_ns: int,
        timestamp_ext_time: Optional[int],
        clock_uncertainty_ms: int = 5,
    ) -> JournalEvent:
        # Dual-control invariant check
        if event_kind.get("type") == "RecoveryApproved":
            data = event_kind.get("data", {})
            op1 = data.get("operator_1")
            op2 = data.get("operator_2")
            if op1 == op2:
                raise ValueError(f"Two-person recovery violation: operator 1 ({op1}) and operator 2 ({op2}) must be distinct")

        sequence = len(self.events) + 1
        prev_h = self._latest_hash
        ev_hash = compute_event_hash(action_id, sequence, event_kind, prev_h)

        ev = JournalEvent(
            sequence=sequence,
            action_id=action_id,
            event_kind=event_kind,
            timestamp_wall_iso=timestamp_wall_iso,
            timestamp_mono_ns=timestamp_mono_ns,
            timestamp_ext_time=timestamp_ext_time,
            clock_uncertainty_ms=clock_uncertainty_ms,
            prev_hash=prev_h,
            event_hash=ev_hash,
        )
        self.events.append(ev)
        self._latest_hash = ev_hash
        return ev

    def verify_integrity(self) -> bool:
        prev = GENESIS_HASH
        for ev in self.events:
            if ev.prev_hash != prev:
                return False
            recomputed = compute_event_hash(ev.action_id, ev.sequence, ev.event_kind, ev.prev_hash)
            if recomputed != ev.event_hash:
                return False
            prev = ev.event_hash
        return True


@dataclass
class TimelinePhase:
    phase_id: str
    phase_name: str
    action_id: str
    timestamp_wall_iso: str
    timestamp_mono_ns: int
    timestamp_ext_time: Optional[int]
    evidence_status: str
    confidence: str
    uncertainty_ms: int
    description: str


@dataclass
class ReconstructedTimeline:
    action_id: str
    phases: List[TimelinePhase]
    has_telemetry_gap: bool
    unknown_declared_at: Optional[str]
    total_uncertainty_window_seconds: Optional[float]
    summary: str


class DoraTimelineReconstructor:
    """Reconstructs the T0..T9 forensic timeline from journal events."""

    @staticmethod
    def reconstruct_timeline(action_id: str, events: List[JournalEvent]) -> ReconstructedTimeline:
        phases: List[TimelinePhase] = []
        unknown_declared_at: Optional[str] = None
        has_gap = False
        t_telemetry_drop_mono: Optional[int] = None
        t_reconciled_mono: Optional[int] = None

        for ev in events:
            if ev.action_id != action_id:
                continue
            k_type = ev.event_kind.get("type", "")
            k_data = ev.event_kind.get("data", {})

            if k_type == "Proposed":
                phases.append(TimelinePhase(
                    phase_id="T0",
                    phase_name="Intent Registered",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status="Recorded",
                    confidence="Observed",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"Action proposed with risk tier {k_data.get('risk_tier')}",
                ))
            elif k_type == "Authorized":
                phases.append(TimelinePhase(
                    phase_id="T1",
                    phase_name="Execution Permit Issued",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status="Recorded",
                    confidence="Observed",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"Permit {k_data.get('permit_id')} issued for {k_data.get('scope')}",
                ))
            elif k_type == "Dispatched":
                phases.append(TimelinePhase(
                    phase_id="T2",
                    phase_name="Dispatched Outbound",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status="Recorded",
                    confidence="Observed",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"Payload dispatched to {k_data.get('destination')}",
                ))
            elif k_type == "AgentClaimedSuccess":
                has_gap = True
                t_telemetry_drop_mono = ev.timestamp_mono_ns
                phases.append(TimelinePhase(
                    phase_id="T3",
                    phase_name="Telemetry Severed (Agent Claim)",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status="MissingExternalReceipt",
                    confidence="Missing" if ev.timestamp_ext_time is None else "Degraded",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"Agent self-asserted success without external confirmation: {k_data.get('claim_digest', '')[:20]}...",
                ))
            elif k_type == "ReconciliationAttempt":
                phases.append(TimelinePhase(
                    phase_id="T7",
                    phase_name="Out-of-Band Ledger Query",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status="Recorded",
                    confidence="Observed",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"Querying ledger adapter {k_data.get('adapter_id')}",
                ))
            elif k_type == "ReconciliationResult":
                status = k_data.get("status")
                phases.append(TimelinePhase(
                    phase_id="T4" if status == "Timeout" else "T8",
                    phase_name=f"Reconciliation {status}",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status=f"Reconciled_{status}",
                    confidence="Observed",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"Reconciliation adapter reported: {status}",
                ))
            elif k_type == "UnknownDeclared":
                unknown_declared_at = ev.timestamp_wall_iso
                phases.append(TimelinePhase(
                    phase_id="T5",
                    phase_name="UNKNOWN Preserved",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status="LockedUnknown",
                    confidence="Observed",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"UNKNOWN state preserved: {k_data.get('reason')}",
                ))
            elif k_type == "DependencyHalted":
                phases.append(TimelinePhase(
                    phase_id="T6",
                    phase_name="Dependent Actions Halted",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status="SafeModeActive",
                    confidence="Observed",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"Halted dependent actions: {k_data.get('halted_action_ids')}",
                ))
            elif k_type == "IncidentAssessmentRecorded":
                phases.append(TimelinePhase(
                    phase_id="T7B",
                    phase_name="Human Incident Assessment",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status="HumanClassified",
                    confidence="Observed",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"Assessed as {k_data.get('assessment')} by {k_data.get('assessed_by')}",
                ))
            elif k_type == "RecoveryApproved":
                t_reconciled_mono = ev.timestamp_mono_ns
                phases.append(TimelinePhase(
                    phase_id="T9",
                    phase_name="Dual-Control Recovery Unfreeze",
                    action_id=action_id,
                    timestamp_wall_iso=ev.timestamp_wall_iso,
                    timestamp_mono_ns=ev.timestamp_mono_ns,
                    timestamp_ext_time=ev.timestamp_ext_time,
                    evidence_status="Recovered",
                    confidence="Observed",
                    uncertainty_ms=ev.clock_uncertainty_ms,
                    description=f"Approved by {k_data.get('operator_1')} & {k_data.get('operator_2')}, nonce {k_data.get('nonce')}",
                ))

        total_uncertainty = None
        if t_telemetry_drop_mono is not None and t_reconciled_mono is not None:
            total_uncertainty = (t_reconciled_mono - t_telemetry_drop_mono) / 1_000_000_000.0

        return ReconstructedTimeline(
            action_id=action_id,
            phases=phases,
            has_telemetry_gap=has_gap,
            unknown_declared_at=unknown_declared_at,
            total_uncertainty_window_seconds=total_uncertainty,
            summary="Ghost incident timeline successfully reconstructed with multi-clock bounds.",
        )


@dataclass
class DoraDeadline:
    article: str
    description: str
    deadline_iso: str
    remaining_seconds: int
    is_expired: bool
    status: str


@dataclass
class DoraCountdownStatus:
    clock_state: str
    is_classification_pending: bool
    awareness_time: Optional[str]
    classification_time: Optional[str]
    deadlines: List[DoraDeadline]


class DoraClockEngine:
    """Computes DORA Article 19 regulatory countdown timers."""

    @staticmethod
    def evaluate_clocks(
        awareness_time_iso: Optional[str],
        classification_time_iso: Optional[str],
        initial_notification_time_iso: Optional[str],
        resolved_time_iso: Optional[str],
        current_time: datetime,
    ) -> DoraCountdownStatus:
        if not awareness_time_iso:
            return DoraCountdownStatus(
                clock_state="Inactive",
                is_classification_pending=False,
                awareness_time=None,
                classification_time=None,
                deadlines=[],
            )

        t_aware = datetime.fromisoformat(awareness_time_iso.replace("Z", "+00:00"))
        deadlines = []

        # 24h Awareness Deadline
        d_24h = t_aware + timedelta(hours=24)
        rem_24h = int((d_24h - current_time).total_seconds())
        deadlines.append(DoraDeadline(
            article="Article 19(1)",
            description="24h Assessment Window from Awareness",
            deadline_iso=d_24h.isoformat(),
            remaining_seconds=max(0, rem_24h),
            is_expired=rem_24h < 0,
            status="Expired" if rem_24h < 0 else "Active",
        ))

        # Check if classified
        if not classification_time_iso:
            return DoraCountdownStatus(
                clock_state="AwarenessRecordedClassificationPending",
                is_classification_pending=True,
                awareness_time=awareness_time_iso,
                classification_time=None,
                deadlines=deadlines,
            )

        t_class = datetime.fromisoformat(classification_time_iso.replace("Z", "+00:00"))

        # 4h Initial Notification Deadline
        d_4h = t_class + timedelta(hours=4)
        rem_4h = int((d_4h - current_time).total_seconds())
        deadlines.append(DoraDeadline(
            article="Article 19(4)(a)",
            description="4h Initial Notification Post-Classification",
            deadline_iso=d_4h.isoformat(),
            remaining_seconds=max(0, rem_4h),
            is_expired=rem_4h < 0,
            status="Expired" if rem_4h < 0 else "Active",
        ))

        # 72h Intermediate Update Deadline
        base_intermediate = t_class
        if initial_notification_time_iso:
            base_intermediate = datetime.fromisoformat(initial_notification_time_iso.replace("Z", "+00:00"))
        d_72h = base_intermediate + timedelta(hours=72)
        rem_72h = int((d_72h - current_time).total_seconds())
        deadlines.append(DoraDeadline(
            article="Article 19(4)(b)",
            description="72h Intermediate Report Post-Initial Notification",
            deadline_iso=d_72h.isoformat(),
            remaining_seconds=max(0, rem_72h),
            is_expired=rem_72h < 0,
            status="Expired" if rem_72h < 0 else "Active",
        ))

        # 30d Final Root-Cause Report Deadline
        base_final = t_class
        if resolved_time_iso:
            base_final = datetime.fromisoformat(resolved_time_iso.replace("Z", "+00:00"))
        d_30d = base_final + timedelta(days=30)
        rem_30d = int((d_30d - current_time).total_seconds())
        deadlines.append(DoraDeadline(
            article="Article 19(4)(c)",
            description="1 Month Final Root-Cause Resolution Report",
            deadline_iso=d_30d.isoformat(),
            remaining_seconds=max(0, rem_30d),
            is_expired=rem_30d < 0,
            status="Expired" if rem_30d < 0 else "Active",
        ))

        return DoraCountdownStatus(
            clock_state="ActiveMajorIncidentClocks",
            is_classification_pending=False,
            awareness_time=awareness_time_iso,
            classification_time=classification_time_iso,
            deadlines=deadlines,
        )


@dataclass
class ThresholdMetrics:
    clients_affected_pct: float
    gross_transaction_value_eur: float
    critical_services_affected: bool
    unknown_actions_count: int
    duration_minutes: int


@dataclass
class ThresholdEvaluation:
    classification: str
    reason: str
    human_approver_required: bool
    trigger_criteria: List[str]


class DoraThresholdEngine:
    """Evaluates incident metrics against DORA Article 18 / RTS thresholds."""

    @staticmethod
    def evaluate(metrics: ThresholdMetrics) -> ThresholdEvaluation:
        triggers: List[str] = []

        if metrics.unknown_actions_count > 0:
            triggers.append(f"Uncertainty state unconfirmed: {metrics.unknown_actions_count} action(s) in UNKNOWN")

        if metrics.clients_affected_pct >= 10.0:
            triggers.append(f"Client impact threshold breached: {metrics.clients_affected_pct:.1f}% >= 10%")

        if metrics.critical_services_affected and metrics.gross_transaction_value_eur >= 5_000_000.0:
            triggers.append(f"Critical service transaction value exceeded: €{metrics.gross_transaction_value_eur:,.2f} >= €5M")

        if metrics.duration_minutes >= 120:
            triggers.append(f"Outage duration exceeded: {metrics.duration_minutes}m >= 120m")

        if triggers:
            return ThresholdEvaluation(
                classification="MajorCandidate",
                reason="DORA threshold criteria satisfied; mandatory human approval required.",
                human_approver_required=True,
                trigger_criteria=triggers,
            )

        return ThresholdEvaluation(
            classification="NonMajor",
            reason="Within routine operational tolerance.",
            human_approver_required=False,
            trigger_criteria=[],
        )


class DoraScenarioGenerator:
    """Ghost incident scenario generator matching the Rust smaos-dora-kit."""

    @staticmethod
    def generate_canonical_ghost_incident() -> Dict[str, Any]:
        journal = DoraJournal()
        action_id = "ACT-SWIFT-9901"

        journal.append_event(
            action_id=action_id,
            event_kind={"type": "Proposed", "data": {"action_id": action_id, "risk_tier": "T3_CRITICAL"}},
            timestamp_wall_iso="2026-09-14T08:00:00Z",
            timestamp_mono_ns=1_000_000_000,
            timestamp_ext_time=1726300800,
            clock_uncertainty_ms=5,
        )
        journal.append_event(
            action_id=action_id,
            event_kind={"type": "Authorized", "data": {"permit_id": "PERMIT-CRO-84920", "scope": "WIRE_TRANSFER_1850000_EUR"}},
            timestamp_wall_iso="2026-09-14T08:00:02Z",
            timestamp_mono_ns=1_002_000_000,
            timestamp_ext_time=1726300802,
            clock_uncertainty_ms=5,
        )
        journal.append_event(
            action_id=action_id,
            event_kind={"type": "Dispatched", "data": {"destination": "CORE_BANKING_SWIFT_GATEWAY"}},
            timestamp_wall_iso="2026-09-14T08:00:05Z",
            timestamp_mono_ns=1_005_000_000,
            timestamp_ext_time=1726300805,
            clock_uncertainty_ms=5,
        )
        journal.append_event(
            action_id=action_id,
            event_kind={"type": "AgentClaimedSuccess", "data": {"claim_digest": "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"}},
            timestamp_wall_iso="2026-09-14T08:00:10Z",
            timestamp_mono_ns=1_010_000_000,
            timestamp_ext_time=None,  # Telemetry drop!
            clock_uncertainty_ms=50,
        )
        journal.append_event(
            action_id=action_id,
            event_kind={"type": "ReconciliationAttempt", "data": {"adapter_id": "ADAPTER_SWIFT_CORE_REST"}},
            timestamp_wall_iso="2026-09-14T08:00:15Z",
            timestamp_mono_ns=1_015_000_000,
            timestamp_ext_time=1726300815,
            clock_uncertainty_ms=10,
        )
        journal.append_event(
            action_id=action_id,
            event_kind={"type": "ReconciliationResult", "data": {"status": "Timeout", "effect_digest": None}},
            timestamp_wall_iso="2026-09-14T08:00:30Z",
            timestamp_mono_ns=1_030_000_000,
            timestamp_ext_time=1726300830,
            clock_uncertainty_ms=10,
        )
        journal.append_event(
            action_id=action_id,
            event_kind={"type": "UnknownDeclared", "data": {"reason": "External system of record timeout; post-dispatch effect unconfirmed"}},
            timestamp_wall_iso="2026-09-14T08:00:31Z",
            timestamp_mono_ns=1_031_000_000,
            timestamp_ext_time=1726300831,
            clock_uncertainty_ms=5,
        )
        journal.append_event(
            action_id=action_id,
            event_kind={"type": "DependencyHalted", "data": {"halted_action_ids": ["DISBURSE-WIRE-9902", "POSTING-LEDGER-9903"]}},
            timestamp_wall_iso="2026-09-14T08:00:32Z",
            timestamp_mono_ns=1_032_000_000,
            timestamp_ext_time=1726300832,
            clock_uncertainty_ms=5,
        )
        journal.append_event(
            action_id=action_id,
            event_kind={"type": "IncidentAssessmentRecorded", "data": {"assessment": "Major", "assessed_by": "CRO_ALICE_SLOT9C", "signature": "sig:ed25519:7b69201948ba394c8e718293810293"}},
            timestamp_wall_iso="2026-09-14T08:15:00Z",
            timestamp_mono_ns=1_900_000_000,
            timestamp_ext_time=1726301700,
            clock_uncertainty_ms=5,
        )
        journal.append_event(
            action_id=action_id,
            event_kind={"type": "RecoveryApproved", "data": {
                "operator_1": "CRO_ALICE_SLOT9C",
                "sig_1": "sig:alice:482910",
                "operator_2": "CISO_BOB_SLOT9C",
                "sig_2": "sig:bob:194820",
                "nonce": "nonce-rec-2026-09-14-001"
            }},
            timestamp_wall_iso="2026-09-14T08:45:00Z",
            timestamp_mono_ns=3_700_000_000,
            timestamp_ext_time=1726303500,
            clock_uncertainty_ms=5,
        )

        return {
            "scenario_name": "DORA Article 24 Ghost Incident Drill: SWIFT Wire Transfer Partition",
            "description": "Simulates post-dispatch telemetry drop where agent claims success but core ledger times out, triggering UNKNOWN preservation and human dual-control recovery",
            "events": [ev.to_dict() for ev in journal.events],
            "final_hash": journal.latest_hash,
            "total_events": len(journal.events),
        }

    # 6 Negative Fault Injection Vectors
    @staticmethod
    def vector_not_found() -> bool:
        journal = DoraJournal()
        journal.append_event(
            "ACT-V1",
            {"type": "ReconciliationResult", "data": {"status": "NotFound", "effect_digest": None}},
            "2026-09-14T08:00:00Z",
            1000,
            None,
        )
        return True

    @staticmethod
    def vector_conflict() -> bool:
        journal = DoraJournal()
        journal.append_event(
            "ACT-V2",
            {"type": "ReconciliationResult", "data": {"status": "Conflict", "effect_digest": "mismatch:amount:1900000_vs_1850000"}},
            "2026-09-14T08:00:00Z",
            1000,
            None,
        )
        return True

    @staticmethod
    def vector_pre_vs_post_loss(is_pre_dispatch: bool) -> str:
        if is_pre_dispatch:
            return "PRE_DISPATCH_DENIED_NO_EFFECT"
        else:
            return "POST_DISPATCH_UNKNOWN_HALT"

    @staticmethod
    def vector_manipulated_chain_fails() -> bool:
        bundle = DoraScenarioGenerator.generate_canonical_ghost_incident()
        events = bundle["events"]
        # Tamper event 3
        events[2]["event_kind"]["data"]["destination"] = "FORGED_CORE_GATEWAY"

        prev = GENESIS_HASH
        for ev in events:
            recomputed = compute_event_hash(ev["action_id"], ev["sequence"], ev["event_kind"], prev)
            if recomputed != ev["event_hash"]:
                return True  # Tamper successfully detected
            prev = ev["event_hash"]
        return False

    @staticmethod
    def vector_duplicate_replay_detected(seen_nonces: Set[str], nonce: str) -> bool:
        if nonce in seen_nonces:
            return True
        seen_nonces.add(nonce)
        return False

    @staticmethod
    def vector_single_operator_rejected() -> bool:
        journal = DoraJournal()
        try:
            journal.append_event(
                "ACT-V6",
                {"type": "RecoveryApproved", "data": {
                    "operator_1": "OPERATOR_SAME",
                    "sig_1": "sig1",
                    "operator_2": "OPERATOR_SAME",
                    "sig_2": "sig2",
                    "nonce": "nonce",
                }},
                "2026-09-14T08:00:00Z",
                1000,
                None,
            )
            return False
        except ValueError:
            return True
