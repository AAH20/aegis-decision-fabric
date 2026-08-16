from __future__ import annotations

import json
from pathlib import Path

from adf.schema import ConfidenceResult, Disposition, NormalizedAlert, TriageResult


class SuppressLedger:
    """FP suppression ledger (blue-hive / SNR role)."""

    def __init__(self) -> None:
        self._keys: set[str] = set()

    @staticmethod
    def key_for(alert: NormalizedAlert) -> str:
        return "|".join(
            [
                alert.source,
                alert.signature_id or "",
                alert.title,
                alert.src_ip or "",
                alert.dst_ip or "",
            ]
        )

    def add(self, alert: NormalizedAlert) -> None:
        self._keys.add(self.key_for(alert))

    def is_suppressed(self, alert: NormalizedAlert) -> bool:
        return self.key_for(alert) in self._keys

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        for k in data.get("keys", []):
            self._keys.add(str(k))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"keys": sorted(self._keys)}, indent=2) + "\n", encoding="utf-8")


def triage(
    alert: NormalizedAlert,
    confidence: ConfidenceResult,
    ledger: SuppressLedger | None = None,
) -> TriageResult:
    notes: list[str] = []
    ledger = ledger or SuppressLedger()

    if ledger.is_suppressed(alert):
        return TriageResult(
            alert_id=alert.alert_id,
            disposition=Disposition.SUPPRESS_FP,
            tier="T1",
            notes=["matched_fp_suppress_ledger"],
        )

    if confidence.band == "low":
        notes.append("low_composite_auto_triage_queue")
        return TriageResult(
            alert_id=alert.alert_id,
            disposition=Disposition.TRIAGE,
            tier="T1",
            notes=notes,
        )

    if confidence.band == "medium":
        notes.append("medium_composite_t2_enrich")
        return TriageResult(
            alert_id=alert.alert_id,
            disposition=Disposition.TRIAGE,
            tier="T2",
            notes=notes,
        )

    notes.append("high_composite_t3_decide")
    return TriageResult(
        alert_id=alert.alert_id,
        disposition=Disposition.ESCALATE,
        tier="T3",
        notes=notes,
    )
