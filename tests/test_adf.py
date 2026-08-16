from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adf.confidence import composite_confidence
from adf.decide import decide
from adf.gate import gate_tool, set_kill_switch
from adf.ingest import from_ocsf_finding, from_snort_snortml, load_fixture
from adf.ledger import ActionLedger
from adf.pipeline import run_paths, summarize_cost
from adf.schema import Disposition, GateMode
from adf.triage import SuppressLedger, triage


def test_ml_never_equals_signature_fix_now():
    alert = from_snort_snortml(
        {
            "alert_id": "t-ml",
            "gid": 411,
            "snortml_score": 0.99,
            "msg": "ml only",
            "severity": "high",
        }
    )
    conf = composite_confidence(alert)
    tri = triage(alert, conf)
    page = decide(alert, conf, tri)
    assert conf.never_equate_ml_to_signature is True
    assert alert.is_ml_only is True
    assert page.decision == Disposition.ESCALATE
    assert page.deny_auto_contain is True
    assert "high_ml_alone_does_not_authorize_contain" in page.evidence
    g = gate_tool("contain_host", page, mode=GateMode.ALLOW, alert=alert)
    assert g.allowed is False
    assert g.reason == "ml_only_deny_auto_contain"


def test_signature_high_can_fix_now_but_gate_simulates():
    alert = from_snort_snortml(
        {
            "alert_id": "t-sig",
            "gid": 1,
            "sid": "1:1",
            "msg": "sig",
            "severity": "high",
        }
    )
    conf = composite_confidence(alert)
    tri = triage(alert, conf)
    page = decide(alert, conf, tri)
    assert page.decision == Disposition.FIX_NOW
    g = gate_tool("contain_host", page, mode=GateMode.SIMULATE, alert=alert)
    assert g.allowed is False
    assert g.mode == GateMode.SIMULATE
    assert "simulate" in g.reason


def test_corroborated_ocsf_fix_now():
    alert = from_ocsf_finding(
        {
            "id": "ocsf-c",
            "severity": "high",
            "is_ml_only": False,
            "is_corroborated": True,
            "finding_info": {
                "uid": "ocsf-c",
                "title": "corroborated",
                "analytic": {"type_id": 1, "uid": "r1"},
            },
        }
    )
    conf = composite_confidence(alert)
    page = decide(alert, conf, triage(alert, conf))
    assert alert.is_corroborated is True
    assert page.decision == Disposition.FIX_NOW
    assert page.is_corroborated is True


def test_kill_switch_denies_contain():
    set_kill_switch(True)
    alert = from_snort_snortml(
        {"alert_id": "t-ks", "gid": 1, "sid": "1:1", "msg": "sig", "severity": "high"}
    )
    conf = composite_confidence(alert)
    page = decide(alert, conf, triage(alert, conf))
    g = gate_tool("contain_host", page, mode=GateMode.ALLOW, alert=alert)
    assert g.allowed is False
    assert g.reason == "kill_switch_engaged"
    set_kill_switch(False)


def test_action_ledger_records_denies():
    ledger = ActionLedger()
    alert = from_snort_snortml(
        {"alert_id": "t-led", "gid": 411, "snortml_score": 0.99, "msg": "ml", "severity": "high"}
    )
    page = decide(alert, composite_confidence(alert), triage(alert, composite_confidence(alert)))
    gate_tool("block_ip", page, mode=GateMode.ALLOW, alert=alert, ledger=ledger)
    assert ledger.denied_contains() == 1
    assert ledger.entries[0]["reason"] == "ml_only_deny_auto_contain"


def test_fixtures_load_and_pipeline():
    paths = [
        ROOT / "fixtures" / "snortml_beachhead.json",
        ROOT / "fixtures" / "splunk_notables.json",
        ROOT / "fixtures" / "ocsf_dual_signal.json",
    ]
    results = run_paths(paths, feedback_dir=ROOT / "artifacts" / "test_feedback")
    assert len(results) == 8
    ids = {r.alert_id for r in results}
    assert "ml-sqli-002" in ids
    assert "notable-1001" in ids
    assert "ocsf-ml-001" in ids
    cost = summarize_cost(results)
    assert cost["ml_only_escalated"] >= 1
    assert cost["estimated_total_avoidance_usd"] > 0


def test_suppress_ledger():
    ledger = SuppressLedger()
    alert = from_snort_snortml(
        {
            "alert_id": "fp1",
            "sid": "1:999999",
            "msg": "Known scanner FP",
            "src_addr": "192.0.2.99",
            "dst_addr": "10.0.0.5",
        }
    )
    ledger.add(alert)
    conf = composite_confidence(alert)
    tri = triage(alert, conf, ledger)
    assert tri.disposition == Disposition.SUPPRESS_FP


if __name__ == "__main__":
    test_ml_never_equals_signature_fix_now()
    test_signature_high_can_fix_now_but_gate_simulates()
    test_corroborated_ocsf_fix_now()
    test_kill_switch_denies_contain()
    test_action_ledger_records_denies()
    test_fixtures_load_and_pipeline()
    test_suppress_ledger()
    print("all tests passed")
