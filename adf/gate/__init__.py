from __future__ import annotations

from adf.schema import DecisionPage, Disposition, GateMode, GateVerdict


# Kill-switch: when True, all contain tools forced to DENY
KILL_SWITCH = False


def set_kill_switch(enabled: bool) -> None:
    global KILL_SWITCH
    KILL_SWITCH = enabled


def gate_tool(tool: str, decision: DecisionPage, mode: GateMode = GateMode.SIMULATE) -> GateVerdict:
    """
    Aegis commander gate: deny/simulate/allow before remediation tools.
    Default for contain-class tools is SIMULATE unless FIX_NOW + allow requested + kill-switch off.
    """
    contain_tools = {"contain_host", "block_ip", "quarantine", "fmc_block"}

    if KILL_SWITCH:
        return GateVerdict(tool=tool, mode=GateMode.DENY, allowed=False, reason="kill_switch_engaged")

    if tool in contain_tools:
        if decision.decision != Disposition.FIX_NOW:
            return GateVerdict(
                tool=tool,
                mode=GateMode.DENY,
                allowed=False,
                reason="contain_requires_fix_now_decision",
            )
        if mode == GateMode.ALLOW:
            return GateVerdict(
                tool=tool,
                mode=GateMode.ALLOW,
                allowed=True,
                reason="fix_now_and_explicit_allow",
            )
        return GateVerdict(
            tool=tool,
            mode=GateMode.SIMULATE,
            allowed=False,
            reason="default_simulate_contain_no_side_effects",
        )

    # Read-only enrich tools
    if tool in {"splunk_query", "ticket_create", "enrich_kev"}:
        return GateVerdict(tool=tool, mode=GateMode.ALLOW, allowed=True, reason="read_or_ticket_allowed")

    return GateVerdict(tool=tool, mode=GateMode.DENY, allowed=False, reason="unknown_tool_deny_by_default")
