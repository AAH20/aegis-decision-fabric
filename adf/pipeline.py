from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from adf.confidence import composite_confidence
from adf.cost import estimate_cost_avoidance
from adf.decide import decide
from adf.feedback import emit_feedback
from adf.gate import gate_tool
from adf.ingest import load_fixtures
from adf.ledger import ActionLedger
from adf.schema import Disposition, GateMode, NormalizedAlert
from adf.triage import SuppressLedger, triage


@dataclass
class PipelineResult:
    alert_id: str
    confidence: dict[str, Any]
    triage: dict[str, Any]
    decision: dict[str, Any]
    gate: dict[str, Any] | None = None
    feedback_files: list[str] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_one(
    alert: NormalizedAlert,
    ledger: SuppressLedger | None = None,
    feedback_dir: Path | None = None,
    contain_mode: GateMode = GateMode.SIMULATE,
    action_ledger: ActionLedger | None = None,
) -> PipelineResult:
    t0 = time.perf_counter()
    ledger = ledger or SuppressLedger()
    conf = composite_confidence(alert)
    tri = triage(alert, conf, ledger)
    page = decide(alert, conf, tri)

    gate = None
    # Evaluate contain Gate/Prove for FIX_NOW candidates and ML-only deny proofs
    if (
        "contain_candidate" in page.actions
        or page.decision == Disposition.FIX_NOW
        or page.is_ml_only
        or "gate_deny_until_corroboration" in page.actions
    ):
        gate = gate_tool(
            "contain_host",
            page,
            mode=contain_mode,
            alert=alert,
            ledger=action_ledger,
        )

    feedback_files: list[str] = []
    if feedback_dir is not None:
        feedback_files = [str(p) for p in emit_feedback(alert, page, feedback_dir)]

    return PipelineResult(
        alert_id=alert.alert_id,
        confidence=conf.to_dict(),
        triage=tri.to_dict(),
        decision=page.to_dict(),
        gate=gate.to_dict() if gate else None,
        feedback_files=feedback_files,
        latency_ms=round((time.perf_counter() - t0) * 1000, 3),
    )


def run_paths(
    fixture_paths: list[Path],
    feedback_dir: Path | None = None,
    suppress_path: Path | None = None,
    action_ledger_path: Path | None = None,
) -> list[PipelineResult]:
    ledger = SuppressLedger()
    if suppress_path:
        ledger.load(suppress_path)
    action_ledger = ActionLedger(action_ledger_path) if action_ledger_path else ActionLedger()
    alerts = load_fixtures(fixture_paths)
    return [
        run_one(a, ledger=ledger, feedback_dir=feedback_dir, action_ledger=action_ledger)
        for a in alerts
    ]


def summarize_cost(results: list[PipelineResult]) -> dict[str, Any]:
    ml_only = sum(1 for r in results if r.decision.get("is_ml_only"))
    denied = sum(
        1
        for r in results
        if r.gate and r.gate.get("allowed") is False and r.gate.get("reason") == "ml_only_deny_auto_contain"
    )
    # Assume ~8 minutes T1 saved per auto-dispositioned alert
    t1_minutes = len(results) * 8.0
    estimate = estimate_cost_avoidance(
        ml_only_escalated=ml_only,
        false_contain_avoided=denied,
        t1_minutes_saved=t1_minutes,
    )
    return estimate.to_dict()
