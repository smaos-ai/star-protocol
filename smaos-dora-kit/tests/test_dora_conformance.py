"""
Unit and integration tests for smaos_dora_kit.py.
Verifies cryptographic hash chain parity with Rust, DORA regulatory clocks,
T0..T9 timeline reconstruction, and all 6 negative fault injection vectors.
"""

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from smaos_dora_kit import (
    DoraJournal,
    JournalEvent,
    DoraTimelineReconstructor,
    DoraClockEngine,
    DoraThresholdEngine,
    DoraScenarioGenerator,
    ThresholdMetrics,
    compute_event_hash,
    canonicalize_jcs,
    GENESIS_HASH,
)


def test_bundle_matches_rust_export():
    """Verify Python generated bundle matches Rust exported dora_tabletop_bundle.json."""
    here = Path(__file__).resolve().parent.parent
    candidates = [
        here / "dist" / "dora_tabletop_bundle.json",
        Path("dist/dora_tabletop_bundle.json"),
        Path("dora_tabletop_bundle.json"),
    ]
    rust_bundle_path = next((p for p in candidates if p.exists()), candidates[0])
    assert rust_bundle_path.exists(), "dora_tabletop_bundle.json must exist"

    with open(rust_bundle_path, "r", encoding="utf-8") as f:
        rust_bundle = json.load(f)

    py_bundle = DoraScenarioGenerator.generate_canonical_ghost_incident()

    assert py_bundle["total_events"] == 10
    assert py_bundle["final_hash"] == rust_bundle["final_hash"]
    assert py_bundle["scenario_name"] == rust_bundle["scenario_name"]

    for i in range(10):
        py_ev = py_bundle["events"][i]
        rust_ev = rust_bundle["events"][i]
        assert py_ev["sequence"] == rust_ev["sequence"]
        assert py_ev["action_id"] == rust_ev["action_id"]
        assert py_ev["prev_hash"] == rust_ev["prev_hash"]
        assert py_ev["event_hash"] == rust_ev["event_hash"]
        assert py_ev["timestamp_wall_iso"] == rust_ev["timestamp_wall_iso"]


def test_jcs_canonicalization_and_hashing():
    """Verify RFC 8785 JCS serialization sorts keys and strips spaces."""
    obj = {"z": 1, "a": True, "m": [3, 2, 1], "b": {"nested_y": "val", "nested_x": None}}
    jcs = canonicalize_jcs(obj)
    assert jcs == '{"a":true,"b":{"nested_x":null,"nested_y":"val"},"m":[3,2,1],"z":1}'

    # Compute hash
    h = compute_event_hash("ACT-TEST", 1, obj, GENESIS_HASH)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_timeline_reconstruction():
    """Verify T0..T9 forensic timeline reconstruction."""
    bundle = DoraScenarioGenerator.generate_canonical_ghost_incident()
    events = [JournalEvent(**ev) for ev in bundle["events"]]

    timeline = DoraTimelineReconstructor.reconstruct_timeline("ACT-SWIFT-9901", events)
    assert len(timeline.phases) == 10
    assert timeline.has_telemetry_gap is True
    assert timeline.unknown_declared_at == "2026-09-14T08:00:31Z"
    assert timeline.total_uncertainty_window_seconds is not None
    assert timeline.total_uncertainty_window_seconds > 0

    phase_ids = [p.phase_id for p in timeline.phases]
    assert phase_ids == ["T0", "T1", "T2", "T3", "T7", "T4", "T5", "T6", "T7B", "T9"]

    # Verify T3 telemetry gap is marked Missing/Degraded
    t3 = timeline.phases[3]
    assert t3.phase_id == "T3"
    assert t3.confidence == "Missing"
    assert t3.evidence_status == "MissingExternalReceipt"


def test_dora_regulatory_countdown_clocks():
    """Verify Article 19 clock transitions: Awareness -> Pending -> Assessment -> 4h / 72h / 30d."""
    now = datetime(2026, 9, 14, 8, 30, 0, tzinfo=timezone.utc)
    awareness_iso = "2026-09-14T08:00:00Z"

    # 1. Awareness recorded, classification pending
    status1 = DoraClockEngine.evaluate_clocks(
        awareness_time_iso=awareness_iso,
        classification_time_iso=None,
        initial_notification_time_iso=None,
        resolved_time_iso=None,
        current_time=now,
    )
    assert status1.clock_state == "AwarenessRecordedClassificationPending"
    assert status1.is_classification_pending is True
    assert len(status1.deadlines) == 1
    assert status1.deadlines[0].article == "Article 19(1)"
    assert not status1.deadlines[0].is_expired

    # 2. Human classified as Major -> triggers 4h, 72h, 30d
    class_iso = "2026-09-14T08:15:00Z"
    status2 = DoraClockEngine.evaluate_clocks(
        awareness_time_iso=awareness_iso,
        classification_time_iso=class_iso,
        initial_notification_time_iso=None,
        resolved_time_iso=None,
        current_time=now,
    )
    assert status2.clock_state == "ActiveMajorIncidentClocks"
    assert status2.is_classification_pending is False
    assert len(status2.deadlines) == 4

    # 4h deadline
    d_4h = status2.deadlines[1]
    assert d_4h.article == "Article 19(4)(a)"
    assert d_4h.remaining_seconds == int((datetime(2026, 9, 14, 12, 15, 0, tzinfo=timezone.utc) - now).total_seconds())

    # 72h deadline
    d_72h = status2.deadlines[2]
    assert d_72h.article == "Article 19(4)(b)"

    # 30d deadline
    d_30d = status2.deadlines[3]
    assert d_30d.article == "Article 19(4)(c)"


def test_threshold_evaluation_major_candidate():
    """Verify DORA threshold evaluation triggers MajorCandidate when UNKNOWN count > 0."""
    metrics = ThresholdMetrics(
        clients_affected_pct=0.5,
        gross_transaction_value_eur=1_850_000.0,
        critical_services_affected=True,
        unknown_actions_count=1,  # SMAOS differentiator!
        duration_minutes=45,
    )
    eval_res = DoraThresholdEngine.evaluate(metrics)
    assert eval_res.classification == "MajorCandidate"
    assert eval_res.human_approver_required is True
    assert any("UNKNOWN" in trig for trig in eval_res.trigger_criteria)


def test_all_6_negative_fault_injection_vectors():
    """Verify all 6 negative vectors pass fail-closed checks."""
    # 1. NotFound leaves action in uncertain state
    assert DoraScenarioGenerator.vector_not_found() is True

    # 2. Conflict detects mismatch
    assert DoraScenarioGenerator.vector_conflict() is True

    # 3. Pre-dispatch loss denies effect; Post-dispatch loss preserves UNKNOWN
    assert DoraScenarioGenerator.vector_pre_vs_post_loss(True) == "PRE_DISPATCH_DENIED_NO_EFFECT"
    assert DoraScenarioGenerator.vector_pre_vs_post_loss(False) == "POST_DISPATCH_UNKNOWN_HALT"

    # 4. Tampered payload breaks hash chain
    assert DoraScenarioGenerator.vector_manipulated_chain_fails() is True

    # 5. Duplicate reconciliation replay is detected and rejected
    seen = set()
    assert DoraScenarioGenerator.vector_duplicate_replay_detected(seen, "nonce-1") is False
    assert DoraScenarioGenerator.vector_duplicate_replay_detected(seen, "nonce-1") is True  # Replay!

    # 6. Single-operator recovery is rejected
    assert DoraScenarioGenerator.vector_single_operator_rejected() is True
