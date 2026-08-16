from __future__ import annotations

from adf.schema import (
    ConfidenceResult,
    DecisionPage,
    Disposition,
    NormalizedAlert,
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

    if triage_result.disposition == Disposition.SUPPRESS_FP:
        decision = Disposition.ACCEPT
        actions = ["record_fp", "emit_talos_fp_pack"]
        evidence.append("suppressed_known_fp")
    elif confidence.band == "high" and alert.signal_class.value == "signature":
        decision = Disposition.FIX_NOW
        actions = ["contain_candidate", "gate_required", "emit_tp_candidate_note"]
    elif confidence.band == "high":
        # High ML-only still escalates — does not auto FIX NOW
        decision = Disposition.ESCALATE
        actions = ["corroborate", "human_t3", "gate_deny_until_corroboration"]
        evidence.append("high_ml_alone_does_not_authorize_contain")
    elif confidence.band == "medium":
        decision = Disposition.ESCALATE
        actions = ["enrich_asset_kev", "recompute_confidence"]
    else:
        decision = Disposition.ACCEPT
        actions = ["watchlist", "optional_suppress_review"]

    return DecisionPage(
        alert_id=alert.alert_id,
        decision=decision,
        composite=confidence.composite,
        band=confidence.band,
        actions=actions,
        evidence=evidence,
    )
