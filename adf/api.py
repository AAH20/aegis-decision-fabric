from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adf.confidence import composite_confidence
from adf.decide import decide
from adf.gate import gate_tool, set_kill_switch
from adf.ingest import normalize_event
from adf.ledger import ActionLedger
from adf.pipeline import PipelineResult, run_one
from adf.schema import GateMode, NormalizedAlert
from adf.triage import triage


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


def parse_gate_mode(raw: str | None, *, default: GateMode = GateMode.SIMULATE) -> GateMode:
    if not raw:
        return default
    key = str(raw).strip().lower()
    if key == "allow":
        return GateMode.ALLOW
    if key == "deny":
        return GateMode.DENY
    return GateMode.SIMULATE


@dataclass
class FabricApp:
    """In-process Gate/Prove API used by the HTTP server and contract tests."""

    ledger: ActionLedger = field(default_factory=ActionLedger)
    _alerts: dict[str, NormalizedAlert] = field(default_factory=dict)
    _results: dict[str, PipelineResult] = field(default_factory=dict)
    prove_token: str = field(default_factory=lambda: os.environ.get("ADF_PROVE_TOKEN", ""))

    def remember(self, alert: NormalizedAlert, result: PipelineResult) -> None:
        self._alerts[alert.alert_id] = alert
        self._results[alert.alert_id] = result

    def _latest_ledger(self, alert_id: str) -> dict[str, Any] | None:
        rows = self.ledger.by_alert(alert_id)
        return rows[-1] if rows else None

    def _token_ok(self, token: str | None) -> bool:
        expected = self.prove_token.encode("utf-8")
        provided = str(token or "").encode("utf-8")
        if not expected or len(expected) != len(provided):
            return False
        return hmac.compare_digest(expected, provided)

    def envelope(self, result: PipelineResult, alert: NormalizedAlert) -> dict[str, Any]:
        decision = result.decision
        ml_only = bool(decision.get("is_ml_only") or alert.is_ml_only)
        allow_auto_contain = bool(
            decision.get("is_corroborated") or (not ml_only and decision.get("decision") == "fix_now")
        )
        if ml_only:
            allow_auto_contain = False
        gate = result.gate or {}
        led = self._latest_ledger(alert.alert_id)
        return {
            "alert_id": alert.alert_id,
            "source": alert.source,
            "never_equate_ml_to_signature": True,
            "is_ml_only": ml_only,
            "is_corroborated": bool(alert.is_corroborated or decision.get("is_corroborated")),
            "disposition": decision.get("decision"),
            "allow_auto_contain": allow_auto_contain,
            "require_hitl": ml_only or not allow_auto_contain,
            "decision": decision,
            "confidence": result.confidence,
            "triage": result.triage,
            "gate": gate,
            "ledger_id": (led or {}).get("ledger_id"),
            "latency_ms": result.latency_ms,
            "consultation": "https://a2zsoc.com/consultation",
        }

    def decide(self, body: dict[str, Any]) -> dict[str, Any]:
        event = body.get("event") if isinstance(body.get("event"), dict) else body
        adapter = body.get("adapter") if isinstance(body.get("event"), dict) else event.get("adapter")
        alert = normalize_event(event, adapter=str(adapter) if adapter else None)
        result = run_one(alert, action_ledger=self.ledger)
        self.remember(alert, result)
        if not self._latest_ledger(alert.alert_id):
            self.ledger.append(
                alert_id=alert.alert_id,
                tool="decide",
                mode="n/a",
                allowed=False,
                reason=f"disposition_{result.decision.get('decision')}",
            )
        return self.envelope(result, alert)

    def contain(self, body: dict[str, Any]) -> dict[str, Any]:
        tool = str(body.get("tool") or "block_ip")
        requested = parse_gate_mode(body.get("mode"))
        event = body.get("event") if isinstance(body.get("event"), dict) else None
        alert_id = str(body.get("alert_id") or "")

        if event is not None:
            adapter = body.get("adapter")
            alert = normalize_event(event, adapter=str(adapter) if adapter else None)
        elif alert_id and alert_id in self._alerts:
            alert = self._alerts[alert_id]
        else:
            raise KeyError("event_or_alert_id_required")

        conf = composite_confidence(alert)
        page = decide(alert, conf, triage(alert, conf))
        mode = requested
        if requested == GateMode.ALLOW and not self._token_ok(body.get("prove_token")):
            mode = GateMode.SIMULATE
        verdict = gate_tool(tool, page, mode=mode, alert=alert, ledger=self.ledger)
        result = PipelineResult(
            alert_id=alert.alert_id,
            confidence=conf.to_dict(),
            triage=triage(alert, conf).to_dict(),
            decision=page.to_dict(),
            gate=verdict.to_dict(),
        )
        self.remember(alert, result)
        env = self.envelope(result, alert)
        env["gate"] = verdict.to_dict()
        env["contain_side_effects"] = bool(verdict.allowed and verdict.mode.value == "allow")
        env["ledger_id"] = (self._latest_ledger(alert.alert_id) or {}).get("ledger_id")
        return env

    def get_ledger(self, ledger_or_alert_id: str) -> dict[str, Any] | list[dict[str, Any]] | None:
        one = self.ledger.get(ledger_or_alert_id)
        if one is not None:
            return one
        many = self.ledger.by_alert(ledger_or_alert_id)
        if many:
            return many
        return None


def default_app(ledger_path: Path | None = None) -> FabricApp:
    if _truthy(os.environ.get("ADF_KILL_SWITCH")):
        set_kill_switch(True)
    path = ledger_path
    if path is None:
        raw = os.environ.get("ADF_LEDGER")
        path = Path(raw) if raw else None
    return FabricApp(ledger=ActionLedger(path))
