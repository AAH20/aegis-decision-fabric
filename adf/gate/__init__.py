from __future__ import annotations

from adf.ledger import ActionLedger
from adf.schema import DecisionPage, Disposition, GateMode, GateVerdict, NormalizedAlert


# Kill-switch: when True, all contain tools forced to DENY
KILL_SWITCH = False


def set_kill_switch(enabled: bool) -> None:
    global KILL_SWITCH
    KILL_SWITCH = enabled


def gate_tool(
    tool: str,
    decision: DecisionPage,
    mode: GateMode = GateMode.SIMULATE,
    alert: NormalizedAlert | None = None,
    ledger: ActionLedger | None = None,
) -> GateVerdict:
    """
    Aegis commander gate: deny/simulate/allow before remediation tools.

    Hard rules:
    - kill-switch → DENY
    - ML-only / deny_auto_contain → DENY contain tools (never treat ML as signature TP)
    - contain requires FIX_NOW
    - default contain mode is SIMULATE (Gate→Prove; no side effects)
    """
    contain_tools = {"contain_host", "block_ip", "quarantine", "fmc_block"}
    alert_id = decision.alert_id

    def _finish(verdict: GateVerdict) -> GateVerdict:
        if ledger is not None:
            ledger.record(verdict)
        return verdict

    if KILL_SWITCH:
        return _finish(
            GateVerdict(
                tool=tool,
                mode=GateMode.DENY,
                allowed=False,
                reason="kill_switch_engaged",
                alert_id=alert_id,
            )
        )

    if tool in contain_tools:
        ml_blocked = decision.is_ml_only or "gate_deny_until_corroboration" in decision.actions
        if alert is not None:
            ml_blocked = ml_blocked or (alert.is_ml_only and not alert.is_corroborated)
        if ml_blocked:
            return _finish(
                GateVerdict(
                    tool=tool,
                    mode=GateMode.DENY,
                    allowed=False,
                    reason="ml_only_deny_auto_contain",
                    alert_id=alert_id,
                )
            )
        if decision.decision != Disposition.FIX_NOW or decision.deny_auto_contain:
            return _finish(
                GateVerdict(
                    tool=tool,
                    mode=GateMode.DENY,
                    allowed=False,
                    reason="contain_requires_fix_now_decision",
                    alert_id=alert_id,
                )
            )
        if mode == GateMode.ALLOW:
            # Explicit allow still requires Gate/Prove HITL in production Continuous Trust
            return _finish(
                GateVerdict(
                    tool=tool,
                    mode=GateMode.ALLOW,
                    allowed=True,
                    reason="fix_now_and_explicit_allow_hitl",
                    alert_id=alert_id,
                )
            )
        return _finish(
            GateVerdict(
                tool=tool,
                mode=GateMode.SIMULATE,
                allowed=False,
                reason="default_simulate_contain_gate_prove_no_side_effects",
                alert_id=alert_id,
            )
        )

    if tool in {"splunk_query", "ticket_create", "enrich_kev"}:
        return _finish(
            GateVerdict(
                tool=tool,
                mode=GateMode.ALLOW,
                allowed=True,
                reason="read_or_ticket_allowed",
                alert_id=alert_id,
            )
        )

    return _finish(
        GateVerdict(
            tool=tool,
            mode=GateMode.DENY,
            allowed=False,
            reason="unknown_tool_deny_by_default",
            alert_id=alert_id,
        )
    )
