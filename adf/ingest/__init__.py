from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from adf.schema import NormalizedAlert, SignalClass


def _f(v: Any, default: float | None = None) -> float | None:
    if v is None:
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def from_snort_snortml(event: dict[str, Any]) -> NormalizedAlert:
    """Beachhead adapter: Snort 3-like + SnortML GID:411 score fields."""
    gid = event.get("gid") or event.get("generator_id")
    try:
        gid_i = int(gid) if gid is not None else None
    except (TypeError, ValueError):
        gid_i = None

    ml = _f(event.get("ml_score") or event.get("snortml_score") or event.get("probability"))
    sig = event.get("sid") or event.get("signature_id") or event.get("rule")
    is_ml = gid_i == 411 or (ml is not None and not sig)

    return NormalizedAlert(
        alert_id=str(event.get("alert_id") or event.get("event_id") or event.get("id") or "unknown"),
        source="snort3_snortml",
        title=str(event.get("msg") or event.get("message") or event.get("title") or "snort_alert"),
        signal_class=SignalClass.ML if is_ml else SignalClass.SIGNATURE,
        severity=str(event.get("severity") or event.get("priority") or "medium"),
        ml_score=ml,
        signature_id=str(sig) if sig else None,
        gid=gid_i,
        src_ip=event.get("src_addr") or event.get("src_ip"),
        dst_ip=event.get("dst_addr") or event.get("dst_ip"),
        raw=event,
    )


def from_splunk_notable(event: dict[str, Any]) -> NormalizedAlert:
    """Beachhead adapter: Splunk ES notable-shaped event."""
    return NormalizedAlert(
        alert_id=str(event.get("event_id") or event.get("notable_id") or event.get("id") or "unknown"),
        source="splunk_notable",
        title=str(event.get("search_name") or event.get("rule_name") or event.get("title") or "notable"),
        signal_class=SignalClass.SIEM_NOTABLE,
        severity=str(event.get("urgency") or event.get("severity") or "medium"),
        ml_score=_f(event.get("risk_score")),
        signature_id=event.get("rule_id"),
        src_ip=event.get("src") or event.get("src_ip"),
        dst_ip=event.get("dest") or event.get("dst_ip"),
        raw=event,
    )


def load_fixture(path: Path) -> list[NormalizedAlert]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "events" in data:
        events = data["events"]
    elif isinstance(data, list):
        events = data
    else:
        events = [data]

    out: list[NormalizedAlert] = []
    for ev in events:
        src = (ev.get("_adapter") or ev.get("adapter") or "").lower()
        if src in {"splunk", "splunk_notable"} or "notable" in str(ev.get("search_name", "")).lower():
            out.append(from_splunk_notable(ev))
        else:
            out.append(from_snort_snortml(ev))
    return out


def load_fixtures(paths: Iterable[Path]) -> list[NormalizedAlert]:
    alerts: list[NormalizedAlert] = []
    for p in paths:
        alerts.extend(load_fixture(p))
    return alerts
