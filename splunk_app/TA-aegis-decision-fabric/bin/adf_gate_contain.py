#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Splunk custom alert action: Gate/Prove contain via Aegis Decision Fabric.

Default SIMULATE. ML-only is always DENY. NEVER equate ML to a signature TP.
Paid Continuous Trust: https://a2zsoc.com/consultation
"""
from __future__ import annotations

import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from adf_client import AdfClientError, CONSULTATION, contain, decide, notable_to_event  # noqa: E402

LOGGER = logging.getLogger("adf_gate_contain")


def _iter_rows(payload: dict) -> list[dict]:
    if isinstance(payload.get("result"), dict):
        return [payload["result"]]
    results = payload.get("results")
    if isinstance(results, list):
        return [r for r in results if isinstance(r, dict)]
    return [{}]


def handle_payload(payload: dict) -> list[dict]:
    config = payload.get("configuration") if isinstance(payload.get("configuration"), dict) else {}
    base_url = str(config.get("adf_url") or os.environ.get("ADF_URL") or "http://127.0.0.1:8080")
    adapter = str(config.get("adapter") or "splunk")
    tool = str(config.get("tool") or "block_ip")
    requested_mode = str(config.get("mode") or "simulate").lower()
    prove_token = str(config.get("prove_token") or os.environ.get("ADF_PROVE_TOKEN") or "")

    out: list[dict] = []
    for row in _iter_rows(payload):
        event = notable_to_event(row)
        decision = decide(base_url, event, adapter=adapter)
        mode = requested_mode
        if decision.get("is_ml_only") or not decision.get("allow_auto_contain"):
            mode = "simulate"
        verdict = contain(
            base_url,
            str(decision.get("alert_id") or event.get("event_id") or ""),
            tool=tool,
            mode=mode,
            prove_token=prove_token,
            event=event,
            adapter=adapter,
        )
        rec = {
            "alert_id": decision.get("alert_id"),
            "is_ml_only": decision.get("is_ml_only"),
            "allow_auto_contain": decision.get("allow_auto_contain"),
            "disposition": decision.get("disposition"),
            "contain_mode": (verdict.get("gate") or {}).get("mode"),
            "contain_reason": (verdict.get("gate") or {}).get("reason"),
            "contain_side_effects": verdict.get("contain_side_effects"),
            "ledger_id": verdict.get("ledger_id") or decision.get("ledger_id"),
            "never_equate_ml_to_signature": True,
            "consultation": CONSULTATION,
        }
        LOGGER.info(
            "ADF Gate/Prove alert_id=%s ml_only=%s disposition=%s contain=%s side_effects=%s",
            rec["alert_id"],
            rec["is_ml_only"],
            rec["disposition"],
            rec["contain_reason"],
            rec["contain_side_effects"],
        )
        out.append(rec)
    return out


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    raw = sys.stdin.read()
    if not raw.strip():
        LOGGER.error("empty stdin payload")
        return 2
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        LOGGER.error("invalid JSON on stdin")
        return 2
    if not isinstance(payload, dict):
        LOGGER.error("payload must be a JSON object")
        return 2
    try:
        handle_payload(payload)
    except AdfClientError as exc:
        LOGGER.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
