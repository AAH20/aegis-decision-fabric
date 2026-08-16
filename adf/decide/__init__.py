from __future__ import annotations

from adf.schema import (
    ConfidenceResult,
    DecisionPage,
    Disposition,
    NormalizedAlert,
    SignalClass,
    TriageResult,
)


def decide(
    alert: NormalizedAlert,
    confidence: ConfidenceResult,
    triage_result: TriageResult,
) -> DecisionPage:
    """Commander decide: FIX NOW / ACCEPT / ESCALATE (never silent)."""
    evidence = list(confidence.rationale) + list(triage_result.notes)
    actions: list[str] = []
    is_ml_only = confidence.is_ml_only or alert.is_ml_only
    is_corroborated = confidence.is_corroborated or alert.is_corroborated
    deny_auto_contain = True

    if triage_result.disposition == Disposition.SUPPRESS_FP:
        decision = Disposition.ACCEPT
        actions = ["record_fp", "emit_talos_fp_pack"]
        evidence.append("suppressed_known_fp")
        deny_auto_contain = True
    elif is_ml_only:
        # Hard rule: ML-only never authorizes FIX_NOW / contain
        decision = Disposition.ESCALATE if confidence.band in {"high", "medium"} else Disposition.ACCEPT
        actions = ["corroborate", "human_t3", "gate_deny_until_corroboration", "remediation:deny-auto-contain"]
        evidence.append("high_ml_alone_does_not_authorize_contain" if confidence.band == "high" else "ml_only_path")
        deny_auto_contain = True
    elif confidence.band == "high" and (
        is_corroborated
        or alert.signal_class in {SignalClass.SIGNATURE, SignalClass.COMPOSITE}
    ):
        decision = Disposition.FIX_NOW
        actions = ["contain_candidate", "gate_required", "remediation:hitl-required", "emit_tp_candidate_note"]
        evidence.append("gated_fix_now_candidate")
        deny_auto_contain = False  # still Gate/Prove simulate-default; not ungated
    elif confidence.band == "high":
        decision = Disposition.ESCALATE
        actions = ["corroborate", "human_t3", "gate_deny_until_corroboration"]
        evidence.append("high_without_signature_or_corroboration")
        deny_auto_contain = True
    elif confidence.band == "medium":
        decision = Disposition.ESCALATE
        actions = ["enrich_asset_kev", "recompute_confidence"]
        deny_auto_contain = True
    else:
        decision = Disposition.ACCEPT
        actions = ["watchlist", "optional_suppress_review"]
        deny_auto_contain = True

    return DecisionPage(
        alert_id=alert.alert_id,
        decision=decision,
        composite=confidence.composite,
        band=confidence.band,
        actions=actions,
        evidence=evidence,
        is_ml_only=is_ml_only,
        is_corroborated=is_corroborated,
        deny_auto_contain=deny_auto_contain or is_ml_only,
    )
