from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adf.api import FabricApp
from adf.gate import set_kill_switch
from adf.http_app import make_server
from adf.ingest import load_fixture
from adf.schema import GateMode

set_kill_switch(False)


FIXTURES = [
    ROOT / "fixtures" / "snortml_beachhead.json",
    ROOT / "fixtures" / "splunk_notables.json",
    ROOT / "fixtures" / "ocsf_dual_signal.json",
]


def _ml_event() -> dict:
    return {
        "alert_id": "ml-sqli-002",
        "gid": 411,
        "snortml_score": 0.97,
        "msg": "SnortML possible SQLi (ML-only)",
        "severity": "high",
    }


def _sig_event() -> dict:
    return {
        "alert_id": "sig-sqli-001",
        "gid": 1,
        "sid": "1:1000001",
        "msg": "SQL Injection attempt (signature)",
        "severity": "high",
    }


def test_contract_fixtures_via_decide():
    app = FabricApp()
    n = 0
    for path in FIXTURES:
        for alert in load_fixture(path):
            out = app.decide({"event": alert.raw, "adapter": alert.source if alert.source != "snort3_snortml" else "snort"})
            assert out["never_equate_ml_to_signature"] is True
            assert out["ledger_id"]
            n += 1
    assert n == 8


def test_decide_ml_only_denies_contain():
    app = FabricApp()
    out = app.decide(_ml_event())
    assert out["is_ml_only"] is True
    assert out["allow_auto_contain"] is False
    assert out["disposition"] == "escalate"
    assert out["gate"]["reason"] == "ml_only_deny_auto_contain"


def test_decide_signature_simulates_contain():
    app = FabricApp()
    out = app.decide(_sig_event())
    assert out["is_ml_only"] is False
    assert out["disposition"] == "fix_now"
    assert out["gate"]["mode"] == GateMode.SIMULATE.value


def test_sentinel_and_copilot_adapters():
    app = FabricApp()
    sent = app.decide(
        {
            "adapter": "sentinel",
            "event": {
                "object": {
                    "id": "inc-411",
                    "properties": {
                        "title": "Cisco Firepower - SnortML GID 411 ML-only high alert",
                        "description": "is_ml_only dual-signal:ml-only",
                        "severity": "Medium",
                    },
                }
            },
        }
    )
    assert sent["is_ml_only"] is True
    assert sent["allow_auto_contain"] is False
    cop = app.decide(
        {
            "adapter": "copilot",
            "event": {
                "alert_id": "cop-1",
                "incidentText": "SnortML GID 411 ML-only. Do not contain.",
            },
        }
    )
    assert cop["is_ml_only"] is True


def test_contain_allow_without_token_stays_simulate():
    app = FabricApp(prove_token="secret-token-value")
    app.decide(_sig_event())
    out = app.contain({"alert_id": "sig-sqli-001", "tool": "block_ip", "mode": "allow"})
    assert out["contain_side_effects"] is False
    assert out["gate"]["allowed"] is False
    assert out["gate"]["mode"] == "simulate"


def test_contain_ml_only_denies_even_with_token():
    app = FabricApp(prove_token="secret-token-value")
    app.decide(_ml_event())
    out = app.contain(
        {
            "alert_id": "ml-sqli-002",
            "tool": "block_ip",
            "mode": "allow",
            "prove_token": "secret-token-value",
        }
    )
    assert out["contain_side_effects"] is False
    assert out["gate"]["reason"] == "ml_only_deny_auto_contain"


def test_ledger_get_by_id_and_alert():
    app = FabricApp()
    out = app.decide(_ml_event())
    row = app.get_ledger(out["ledger_id"])
    assert isinstance(row, dict)
    assert row["reason"] == "ml_only_deny_auto_contain"
    rows = app.get_ledger("ml-sqli-002")
    assert isinstance(rows, list) and rows


def test_http_live_roundtrip():
    app = FabricApp()
    httpd = make_server("127.0.0.1", 0, app=app)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        health = f"http://{host}:{port}/health"
        last_err: Exception | None = None
        for _ in range(40):
            try:
                with urlopen(health, timeout=1) as resp:
                    json.loads(resp.read().decode())
                last_err = None
                break
            except Exception as exc:  # noqa: BLE001 — startup race
                last_err = exc
                time.sleep(0.05)
        if last_err is not None:
            raise AssertionError(f"server did not become healthy: {last_err}") from last_err
        req = Request(
            f"http://{host}:{port}/v1/decide",
            data=json.dumps(_ml_event()).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode())
        assert body["is_ml_only"] is True
        assert body["allow_auto_contain"] is False
        lid = body["ledger_id"]
        with urlopen(f"http://{host}:{port}/v1/ledger/{lid}", timeout=5) as resp:
            led = json.loads(resp.read().decode())
        assert led["alert_id"] == "ml-sqli-002"
        try:
            urlopen(f"http://{host}:{port}/v1/ledger/does-not-exist", timeout=5)
            raise AssertionError("expected 404")
        except HTTPError as exc:
            assert exc.code == 404
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    test_contract_fixtures_via_decide()
    test_decide_ml_only_denies_contain()
    test_decide_signature_simulates_contain()
    test_sentinel_and_copilot_adapters()
    test_contain_allow_without_token_stays_simulate()
    test_contain_ml_only_denies_even_with_token()
    test_ledger_get_by_id_and_alert()
    test_http_live_roundtrip()
    print("api tests passed")
