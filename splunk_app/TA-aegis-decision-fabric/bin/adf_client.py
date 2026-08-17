# SPDX-License-Identifier: MIT
"""Stdlib HTTP client for Aegis Decision Fabric Gate/Prove (Splunk TA)."""
from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

CONSULTATION = "https://a2zsoc.com/consultation"
DEFAULT_TIMEOUT = 15


class AdfClientError(RuntimeError):
    pass


def validate_adf_url(url: str) -> str:
    raw = (url or "").strip().rstrip("/")
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise AdfClientError("adf_url must be http(s) with a host")
    return raw


def post_json(url: str, body: dict[str, Any], timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    payload = json.dumps(body).encode("utf-8")
    req = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        raise AdfClientError("ADF HTTP %s: %s" % (exc.code, detail)) from exc
    except URLError as exc:
        raise AdfClientError("ADF unreachable: %s" % exc.reason) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AdfClientError("ADF returned non-JSON") from exc
    if not isinstance(data, dict):
        raise AdfClientError("ADF returned a non-object JSON body")
    return data


def decide(base_url: str, event: dict[str, Any], adapter: str = "splunk") -> dict[str, Any]:
    url = validate_adf_url(base_url) + "/v1/decide"
    return post_json(url, {"adapter": adapter, "event": event})


def contain(
    base_url: str,
    alert_id: str,
    tool: str = "block_ip",
    mode: str = "simulate",
    prove_token: str = "",
    event=None,
    adapter: str = "splunk",
):
    url = validate_adf_url(base_url) + "/v1/contain"
    body: dict[str, Any] = {
        "alert_id": alert_id,
        "tool": tool or "block_ip",
        "mode": (mode or "simulate").lower(),
        "adapter": adapter,
    }
    if prove_token:
        body["prove_token"] = prove_token
    if event:
        body["event"] = event
    return post_json(url, body)


def notable_to_event(result):
    """Map a Splunk notable / alert-action result row onto an ADF event."""
    event = dict(result or {})
    if not event.get("event_id"):
        event["event_id"] = str(
            event.get("notable_id")
            or event.get("orig_sid")
            or event.get("sid")
            or event.get("search_name")
            or event.get("rule_name")
            or "splunk-notable"
        )
    return event
