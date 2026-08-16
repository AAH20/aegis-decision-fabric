from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from adf.confidence import composite_confidence
from adf.decide import decide
from adf.feedback import emit_feedback
from adf.gate import gate_tool
from adf.ingest import load_fixtures
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
) -> PipelineResult:
    t0 = time.perf_counter()
    ledger = ledger or SuppressLedger()
    conf = composite_confidence(alert)
    tri = triage(alert, conf, ledger)
    page = decide(alert, conf, tri)

    gate = None
    if "contain_candidate" in page.actions or page.decision == Disposition.FIX_NOW:
        gate = gate_tool("contain_host", page, mode=contain_mode)

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
) -> list[PipelineResult]:
    ledger = SuppressLedger()
    if suppress_path:
        ledger.load(suppress_path)
    alerts = load_fixtures(fixture_paths)
    return [run_one(a, ledger=ledger, feedback_dir=feedback_dir) for a in alerts]
