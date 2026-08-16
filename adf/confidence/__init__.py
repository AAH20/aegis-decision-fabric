from __future__ import annotations

from adf.schema import ConfidenceResult, NormalizedAlert, SignalClass


def composite_confidence(alert: NormalizedAlert) -> ConfidenceResult:
    """
    Composite confidence policy.

    Hard rule: never equate ML score alone to a signature true positive.
    Signature hits start higher; ML (e.g. SnortML GID:411) needs corroboration band.
    """
    rationale: list[str] = ["never_equate_ml_score_to_signature_tp"]
    score = 0.35

    if alert.signal_class == SignalClass.SIGNATURE and alert.signature_id:
        score = 0.82
        rationale.append("signature_match_present")
        if alert.severity.lower() in {"high", "critical", "1"}:
            score = min(0.92, score + 0.08)
            rationale.append("elevated_severity")

    elif alert.signal_class == SignalClass.ML:
        ml = alert.ml_score if alert.ml_score is not None else 0.0
        # ML can reach "high" attention band but must never be treated as signature TP
        score = min(0.84, 0.30 + (ml * 0.55))
        rationale.append(f"ml_score={ml:.3f}_below_signature_equivalence")
        if alert.gid == 411:
            rationale.append("snortml_gid_411")
        if ml >= 0.9:
            score = max(score, 0.86)
            rationale.append("high_ml_attention_band_requires_corroboration")

    elif alert.signal_class == SignalClass.SIEM_NOTABLE:
        risk = alert.ml_score if alert.ml_score is not None else 50.0
        # Splunk risk_score often 0-100
        norm = min(1.0, risk / 100.0) if risk > 1 else risk
        score = 0.4 + (norm * 0.35)
        rationale.append("siem_notable_risk_normalized")

    # Corroboration: signature + ml both present in raw
    raw = alert.raw or {}
    if alert.signature_id and (raw.get("ml_score") or raw.get("snortml_score")):
        score = min(0.95, score + 0.12)
        rationale.append("signature_plus_ml_corroboration")

    if score >= 0.85:
        band = "high"
    elif score >= 0.55:
        band = "medium"
    else:
        band = "low"

    return ConfidenceResult(
        alert_id=alert.alert_id,
        composite=round(score, 4),
        band=band,
        rationale=rationale,
        never_equate_ml_to_signature=True,
    )
