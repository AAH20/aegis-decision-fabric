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


def _b(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        low = v.strip().lower()
        if low in {"true", "1", "yes"}:
            return True
        if low in {"false", "0", "no"}:
            return False
    return None


def _ocsf_flags(event: dict[str, Any]) -> tuple[bool | None, bool | None]:
    finding = event.get("finding_info") if isinstance(event.get("finding_info"), dict) else {}
    is_ml_only = _b(event.get("is_ml_only"))
    if is_ml_only is None:
        is_ml_only = _b(finding.get("is_ml_only"))
    is_corroborated = _b(event.get("is_corroborated"))
    if is_corroborated is None:
        is_corroborated = _b(finding.get("is_corroborated"))
    return is_ml_only, is_corroborated


def from_snort_snortml(event: dict[str, Any]) -> NormalizedAlert:
    """Beachhead adapter: Snort 3-like + SnortML GID:411 score fields."""
    gid = event.get("gid") or event.get("generator_id")
    try:
        gid_i = int(gid) if gid is not None else None
    except (TypeError, ValueError):
        gid_i = None

    ml = _f(event.get("ml_score") or event.get("snortml_score") or event.get("probability"))
    sig = event.get("sid") or event.get("signature_id") or event.get("rule")
    ocsf_ml, ocsf_corr = _ocsf_flags(event)

    is_corroborated = bool(ocsf_corr) or bool(sig and ml is not None)
    is_ml_only = bool(ocsf_ml) if ocsf_ml is not None else (
        (gid_i == 411 or (ml is not None and not sig)) and not is_corroborated
    )

    if is_corroborated:
        signal = SignalClass.COMPOSITE
    elif is_ml_only:
        signal = SignalClass.ML
    else:
        signal = SignalClass.SIGNATURE

    return NormalizedAlert(
        alert_id=str(event.get("alert_id") or event.get("event_id") or event.get("id") or "unknown"),
        source="snort3_snortml",
        title=str(event.get("msg") or event.get("message") or event.get("title") or "snort_alert"),
        signal_class=signal,
        severity=str(event.get("severity") or event.get("priority") or "medium"),
        ml_score=ml,
        signature_id=str(sig) if sig else None,
        gid=gid_i,
        src_ip=event.get("src_addr") or event.get("src_ip"),
        dst_ip=event.get("dst_addr") or event.get("dst_ip"),
        is_ml_only=is_ml_only,
        is_corroborated=is_corroborated,
        raw=event,
    )


def from_splunk_notable(event: dict[str, Any]) -> NormalizedAlert:
    """Beachhead adapter: Splunk ES notable-shaped event."""
    ocsf_ml, ocsf_corr = _ocsf_flags(event)
    is_corroborated = bool(ocsf_corr)
    is_ml_only = bool(ocsf_ml) and not is_corroborated
    if is_corroborated:
        signal = SignalClass.COMPOSITE
    elif is_ml_only:
        signal = SignalClass.ML
    else:
        signal = SignalClass.SIEM_NOTABLE

    return NormalizedAlert(
        alert_id=str(event.get("event_id") or event.get("notable_id") or event.get("id") or "unknown"),
        source="splunk_notable",
        title=str(event.get("search_name") or event.get("rule_name") or event.get("title") or "notable"),
        signal_class=signal,
        severity=str(event.get("urgency") or event.get("severity") or "medium"),
        ml_score=_f(event.get("risk_score")),
        signature_id=event.get("rule_id"),
        src_ip=event.get("src") or event.get("src_ip"),
        dst_ip=event.get("dest") or event.get("dst_ip"),
        is_ml_only=is_ml_only,
        is_corroborated=is_corroborated,
        raw=event,
    )


def from_ocsf_finding(event: dict[str, Any]) -> NormalizedAlert:
    """OCSF Detection Finding–shaped envelope (is_ml_only / is_corroborated)."""
    finding = event.get("finding_info") if isinstance(event.get("finding_info"), dict) else {}
    ocsf_ml, ocsf_corr = _ocsf_flags(event)
    analytic = finding.get("analytic") if isinstance(finding.get("analytic"), dict) else {}
    type_id = analytic.get("type_id") or event.get("analytic_type_id")
    is_corroborated = bool(ocsf_corr)
    is_ml_only = bool(ocsf_ml) if ocsf_ml is not None else (str(type_id) in {"4", "Learning (ML/DL)"} and not is_corroborated)

    if is_corroborated:
        signal = SignalClass.COMPOSITE
    elif is_ml_only or str(type_id) in {"4"}:
        signal = SignalClass.ML
        is_ml_only = True
    else:
        signal = SignalClass.SIGNATURE

    conf = event.get("confidence_score")
    return NormalizedAlert(
        alert_id=str(finding.get("uid") or event.get("alert_id") or event.get("id") or "unknown"),
        source="ocsf_finding",
        title=str(finding.get("title") or event.get("message") or "ocsf_detection_finding"),
        signal_class=signal,
        severity=str(event.get("severity") or "medium"),
        ml_score=_f(conf) if conf is not None else _f(event.get("ml_score")),
        signature_id=str(analytic.get("uid") or "") or None,
        gid=411 if is_ml_only else None,
        src_ip=(event.get("src_endpoint") or {}).get("ip") if isinstance(event.get("src_endpoint"), dict) else event.get("src_ip"),
        dst_ip=(event.get("dst_endpoint") or {}).get("ip") if isinstance(event.get("dst_endpoint"), dict) else event.get("dst_ip"),
        is_ml_only=is_ml_only and not is_corroborated,
        is_corroborated=is_corroborated,
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
        if src in {"ocsf", "ocsf_finding"} or "finding_info" in ev:
            out.append(from_ocsf_finding(ev))
        elif src in {"splunk", "splunk_notable"} or "notable" in str(ev.get("search_name", "")).lower():
            out.append(from_splunk_notable(ev))
        else:
            out.append(from_snort_snortml(ev))
    return out


def load_fixtures(paths: Iterable[Path]) -> list[NormalizedAlert]:
    alerts: list[NormalizedAlert] = []
    for p in paths:
        alerts.extend(load_fixture(p))
    return alerts
