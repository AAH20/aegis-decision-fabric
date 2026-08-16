from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adf.schema import DecisionPage, Disposition, NormalizedAlert


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def talos_fp_pack(alert: NormalizedAlert, decision: DecisionPage) -> dict[str, Any]:
    return {
        "pack_type": "talos_fp_pack",
        "schema_version": "0.1.0",
        "generated_at": _ts(),
        "alert_id": alert.alert_id,
        "source": alert.source,
        "title": alert.title,
        "signature_id": alert.signature_id,
        "gid": alert.gid,
        "ml_score": alert.ml_score,
        "composite": decision.composite,
        "disposition": decision.decision.value,
        "evidence": decision.evidence,
        "request": "Please review as false positive candidate for content/model tuning.",
    }


def tp_candidate_note(alert: NormalizedAlert, decision: DecisionPage) -> dict[str, Any]:
    return {
        "pack_type": "tp_candidate_note",
        "schema_version": "0.1.0",
        "generated_at": _ts(),
        "alert_id": alert.alert_id,
        "source": alert.source,
        "title": alert.title,
        "signature_id": alert.signature_id,
        "gid": alert.gid,
        "ml_score": alert.ml_score,
        "composite": decision.composite,
        "disposition": decision.decision.value,
        "evidence": decision.evidence,
        "suggestion": "Candidate for signature/model reinforcement after human corroboration.",
    }


def emit_feedback(alert: NormalizedAlert, decision: DecisionPage, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if decision.decision == Disposition.ACCEPT and "emit_talos_fp_pack" in decision.actions:
        path = out_dir / f"{alert.alert_id}_talos_fp_pack.json"
        path.write_text(json.dumps(talos_fp_pack(alert, decision), indent=2) + "\n", encoding="utf-8")
        written.append(path)

    if "emit_tp_candidate_note" in decision.actions or decision.decision == Disposition.FIX_NOW:
        path = out_dir / f"{alert.alert_id}_tp_candidate_note.json"
        path.write_text(json.dumps(tp_candidate_note(alert, decision), indent=2) + "\n", encoding="utf-8")
        written.append(path)

    return written
