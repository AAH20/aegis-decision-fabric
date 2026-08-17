from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TA_BIN = ROOT / "splunk_app" / "TA-aegis-decision-fabric" / "bin"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TA_BIN))

from adf.gate import set_kill_switch
from adf.http_app import make_server
from adf.ingest import from_splunk_notable
from adf_client import AdfClientError, validate_adf_url
from adf_gate_contain import handle_payload

set_kill_switch(False)


def _serve():
    from adf.api import FabricApp

    httpd = make_server("127.0.0.1", 0, app=FabricApp())
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    deadline = time.time() + 2
    while time.time() < deadline:
        try:
            from urllib.request import urlopen

            urlopen("http://%s:%s/health" % (host, port), timeout=0.2).read()
            break
        except Exception:
            time.sleep(0.05)
    return httpd, "http://%s:%s" % (host, port)


def test_splunk_adapter_reads_gid411_from_search_name():
    alert = from_splunk_notable(
        {
            "event_id": "notable-ml-411",
            "search_name": "Cisco Firepower - SnortML GID 411 ML-only high alert",
            "urgency": "high",
            "src": "10.1.2.3",
            "dest": "10.9.9.9",
        }
    )
    assert alert.is_ml_only is True
    brute = from_splunk_notable(
        {
            "event_id": "notable-1001",
            "search_name": "Risk - Notable - Brute Force Detected",
            "urgency": "high",
        }
    )
    assert brute.is_ml_only is False


def test_validate_adf_url_rejects_non_http():
    try:
        validate_adf_url("file:///etc/passwd")
        raise AssertionError("expected reject")
    except AdfClientError:
        pass


def test_alert_action_ml_only_has_no_side_effects():
    httpd, base = _serve()
    try:
        rows = handle_payload(
            {
                "configuration": {
                    "adf_url": base,
                    "adapter": "splunk",
                    "mode": "allow",
                    "prove_token": "secret-token-value",
                    "tool": "block_ip",
                },
                "result": {
                    "event_id": "notable-ml-411",
                    "search_name": "Cisco Firepower - SnortML GID 411 ML-only high alert",
                    "urgency": "high",
                    "src": "10.1.2.3",
                    "dest": "10.9.9.9",
                },
            }
        )
        rec = rows[0]
        assert rec["is_ml_only"] is True
        assert rec["allow_auto_contain"] is False
        assert rec["contain_side_effects"] is False
        assert rec["contain_reason"] == "ml_only_deny_auto_contain"
        assert rec["consultation"] == "https://a2zsoc.com/consultation"
        assert rec["never_equate_ml_to_signature"] is True
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_alert_action_signature_stays_simulate_without_matching_token():
    httpd, base = _serve()
    try:
        rows = handle_payload(
            {
                "configuration": {
                    "adf_url": base,
                    "adapter": "snort",
                    "mode": "allow",
                    "tool": "block_ip",
                },
                "result": {
                    "event_id": "sig-sqli-001",
                    "gid": 1,
                    "sid": "1:1000001",
                    "msg": "SQL Injection attempt (signature)",
                    "severity": "high",
                },
            }
        )
        rec = rows[0]
        assert rec["is_ml_only"] is False
        assert rec["contain_side_effects"] is False
        assert rec["contain_mode"] == "simulate"
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    test_splunk_adapter_reads_gid411_from_search_name()
    test_validate_adf_url_rejects_non_http()
    test_alert_action_ml_only_has_no_side_effects()
    test_alert_action_signature_stays_simulate_without_matching_token()
    print("splunk app tests passed")
