from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adf.schema import GateVerdict


class ActionLedger:
    """Append-only Gate/Prove Action Ledger for diligence-ready remediation audit."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._entries: list[dict[str, Any]] = []
        if path is not None and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self._entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    def append(self, **fields: Any) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ledger_id": str(uuid.uuid4()),
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        entry.update(fields)
        self._entries.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        return entry

    def record(self, verdict: GateVerdict, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {
            "alert_id": verdict.alert_id,
            "tool": verdict.tool,
            "mode": verdict.mode.value,
            "allowed": verdict.allowed,
            "reason": verdict.reason,
        }
        if extra:
            payload.update(extra)
        return self.append(**payload)

    def get(self, ledger_id: str) -> dict[str, Any] | None:
        for entry in reversed(self._entries):
            if str(entry.get("ledger_id")) == ledger_id:
                return dict(entry)
        return None

    def by_alert(self, alert_id: str) -> list[dict[str, Any]]:
        return [dict(e) for e in self._entries if str(e.get("alert_id")) == alert_id]

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
