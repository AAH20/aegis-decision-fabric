from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adf.schema import GateVerdict


class ActionLedger:
    """Append-only Gate/Prove Action Ledger for diligence-ready remediation audit."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._entries: list[dict[str, Any]] = []

    def record(self, verdict: GateVerdict, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        entry = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "alert_id": verdict.alert_id,
            "tool": verdict.tool,
            "mode": verdict.mode.value,
            "allowed": verdict.allowed,
            "reason": verdict.reason,
        }
        if extra:
            entry.update(extra)
        self._entries.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        return entry

    @property
    def entries(self) -> list[dict[str, Any]]:
        return list(self._entries)

    def denied_contains(self) -> int:
        return sum(
            1
            for e in self._entries
            if e.get("allowed") is False
            and e.get("tool") in {"contain_host", "block_ip", "quarantine", "fmc_block"}
        )
