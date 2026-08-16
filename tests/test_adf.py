from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adf.confidence import composite_confidence
from adf.decide import decide
from adf.gate import gate_tool, set_kill_switch
from adf.ingest import from_snort_snortml, load_fixture
from adf.pipeline import run_paths
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
    assert page.decision == Disposition.ESCALATE
    assert "high_ml_alone_does_not_authorize_contain" in page.evidence


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
    g = gate_tool("contain_host", page, mode=GateMode.SIMULATE)
    assert g.allowed is False
    assert g.mode == GateMode.SIMULATE


def test_kill_switch_denies_contain():
    set_kill_switch(True)
    alert = from_snort_snortml(
        {"alert_id": "t-ks", "gid": 1, "sid": "1:1", "msg": "sig", "severity": "high"}
    )
    conf = composite_confidence(alert)
    page = decide(alert, conf, triage(alert, conf))
    g = gate_tool("contain_host", page, mode=GateMode.ALLOW)
    assert g.allowed is False
    assert g.reason == "kill_switch_engaged"
    set_kill_switch(False)


def test_fixtures_load_and_pipeline():
    paths = [
        ROOT / "fixtures" / "snortml_beachhead.json",
        ROOT / "fixtures" / "splunk_notables.json",
    ]
    results = run_paths(paths, feedback_dir=ROOT / "artifacts" / "test_feedback")
    assert len(results) == 6
    ids = {r.alert_id for r in results}
    assert "ml-sqli-002" in ids
    assert "notable-1001" in ids


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
    test_kill_switch_denies_contain()
    test_fixtures_load_and_pipeline()
    test_suppress_ledger()
    print("all tests passed")
