from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from adf.schema import NormalizedAlert, SignalClass

_ML_MARKERS = (
    "gid 411",
    "gid:411",
    "gid=411",
    "generator id 411",
    "snortml",
    "snort ml",
    "is_ml_only",
    "ml-only",
    "ml_only",
    "dual-signal:ml-only",
)
_CORR_MARKERS = (
    "is_corroborated",
    "dual-signal:corroborated",
    "signature and ml",
    "signature + ml",
    "signature plus eve",
    "signature plus ml",
)


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
    blob = _blob(
        event.get("search_name"),
        event.get("rule_name"),
        event.get("title"),
        event.get("description"),
        event.get("rule_title"),
        event.get("orig_raw"),
        event.get("_raw"),
    )
    text_ml, text_corr = _flags_from_text(blob)
    is_corroborated = bool(ocsf_corr) or text_corr
    is_ml_only = (bool(ocsf_ml) or text_ml) and not is_corroborated
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


def _blob(*parts: Any) -> str:
    bits: list[str] = []
    for part in parts:
        if part is None:
            continue
        if isinstance(part, (dict, list)):
            bits.append(json.dumps(part).lower())
        else:
            bits.append(str(part).lower())
    return " ".join(bits)


def _flags_from_text(blob: str) -> tuple[bool, bool]:
    text = blob.lower()
    is_corr = any(m in text for m in _CORR_MARKERS)
    is_ml = (any(m in text for m in _ML_MARKERS) or "generatorid=411" in text) and not is_corr
    return is_ml, is_corr


def from_sentinel_incident(event: dict[str, Any]) -> NormalizedAlert:
    """Microsoft Sentinel incident / Logic App triggerBody envelope."""
    obj = event.get("object") if isinstance(event.get("object"), dict) else event
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else obj
    title = props.get("title") or event.get("title") or "sentinel_incident"
    desc = props.get("description") or event.get("description") or ""
    blob = _blob(title, desc, event.get("incidentText"))
    is_ml, is_corr = _flags_from_text(blob)
    if is_corr:
        signal = SignalClass.COMPOSITE
    elif is_ml:
        signal = SignalClass.ML
    else:
        signal = SignalClass.SIEM_NOTABLE
    return NormalizedAlert(
        alert_id=str(obj.get("id") or event.get("alert_id") or event.get("id") or title)[-64:],
        source="sentinel_incident",
        title=str(title),
        signal_class=signal,
        severity=str(props.get("severity") or event.get("severity") or "medium"),
        gid=411 if is_ml else None,
        is_ml_only=is_ml,
        is_corroborated=is_corr,
        raw=event,
    )


def from_soar_container(event: dict[str, Any]) -> NormalizedAlert:
    """Splunk SOAR / Phantom container or dual_signal_containment_gate input."""
    container = event.get("container") if isinstance(event.get("container"), dict) else {}
    title = container.get("name") or event.get("name") or event.get("title") or "soar_container"
    blob = _blob(
        title,
        container.get("description"),
        event.get("context"),
        event.get("generator_id"),
        event.get("classification"),
        event.get("eve_threat_confidence"),
        event.get("disposition"),
    )
    is_ml, is_corr = _flags_from_text(blob)
    gid = event.get("generator_id") or event.get("gid")
    try:
        gid_i = int(gid) if gid is not None else (411 if is_ml else None)
    except (TypeError, ValueError):
        gid_i = 411 if is_ml else None
    if gid_i == 411 and not is_corr:
        is_ml = True
    if is_corr:
        signal = SignalClass.COMPOSITE
    elif is_ml:
        signal = SignalClass.ML
    else:
        signal = SignalClass.SIGNATURE
    return NormalizedAlert(
        alert_id=str(container.get("id") or event.get("alert_id") or event.get("id") or title),
        source="soar_container",
        title=str(title),
        signal_class=signal,
        severity=str(event.get("severity") or "medium"),
        gid=gid_i,
        is_ml_only=is_ml and not is_corr,
        is_corroborated=is_corr,
        raw=event,
    )


def from_copilot_classify(event: dict[str, Any]) -> NormalizedAlert:
    """Security Copilot plugin classify payload (incidentText or DISPOSITION)."""
    disp = str(event.get("DISPOSITION") or event.get("disposition") or "").strip().lower()
    blob = _blob(event.get("incidentText"), event.get("title"), event.get("REASON"), disp)
    is_ml, is_corr = _flags_from_text(blob)
    if disp == "ml_only":
        is_ml, is_corr = True, False
    elif disp == "corroborated":
        is_ml, is_corr = False, True
    elif disp == "signature":
        is_ml, is_corr = False, False
    if is_corr:
        signal = SignalClass.COMPOSITE
    elif is_ml:
        signal = SignalClass.ML
    else:
        signal = SignalClass.SIGNATURE if disp == "signature" else SignalClass.SIEM_NOTABLE
    return NormalizedAlert(
        alert_id=str(event.get("alert_id") or event.get("id") or "copilot-" + str(hash(blob) % 10_000_000)),
        source="copilot_classify",
        title=str(event.get("title") or event.get("incidentText") or disp or "copilot_incident")[:200],
        signal_class=signal,
        severity=str(event.get("severity") or "medium"),
        gid=411 if is_ml else None,
        is_ml_only=is_ml,
        is_corroborated=is_corr,
        raw=event,
    )


def normalize_event(event: dict[str, Any], adapter: str | None = None) -> NormalizedAlert:
    """Route a vendor envelope onto NormalizedAlert."""
    hinted = (adapter or event.get("_adapter") or event.get("adapter") or "").lower()
    if hinted in {"ocsf", "ocsf_finding"}:
        return from_ocsf_finding(event)
    if hinted in {"splunk", "splunk_notable"}:
        return from_splunk_notable(event)
    if hinted in {"sentinel", "sentinel_incident"}:
        return from_sentinel_incident(event)
    if hinted in {"soar", "soar_container", "phantom"}:
        return from_soar_container(event)
    if hinted in {"copilot", "copilot_classify"}:
        return from_copilot_classify(event)
    if hinted in {"snort", "snort3", "snortml", "snort3_snortml"}:
        return from_snort_snortml(event)

    if "finding_info" in event:
        return from_ocsf_finding(event)
    if "notable" in str(event.get("search_name", "")).lower() or hinted.startswith("splunk"):
        return from_splunk_notable(event)
    if isinstance(event.get("object"), dict) or isinstance(event.get("properties"), dict):
        return from_sentinel_incident(event)
    if "incidentText" in event or "DISPOSITION" in event:
        return from_copilot_classify(event)
    if isinstance(event.get("container"), dict) or event.get("generator_id") is not None:
        return from_soar_container(event)
    return from_snort_snortml(event)


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
        out.append(normalize_event(ev))
    return out


def load_fixtures(paths: Iterable[Path]) -> list[NormalizedAlert]:
    alerts: list[NormalizedAlert] = []
    for p in paths:
        alerts.extend(load_fixture(p))
    return alerts
