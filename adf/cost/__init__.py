from __future__ import annotations

from adf.schema import CostAvoidanceEstimate


def estimate_cost_avoidance(
    *,
    ml_only_escalated: int,
    false_contain_avoided: int,
    t1_minutes_saved: float,
    hourly_t1_cost_usd: float = 55.0,
    false_contain_incident_cost_usd: float = 25000.0,
) -> CostAvoidanceEstimate:
    """
    Rough ICP cost-avoidance model for Continuous Trust / Gate Packet sales talks.

    Defaults are conservative mid-market SOC assumptions — not a binding quote.
    """
    notes = [
        "illustrative_not_a_quote",
        "ml_only_escalated_avoids_treating_ml_as_signature_tp",
        "false_contain_avoided_counts_gate_denies_on_contain_tools",
        "t1_minutes_saved_from_auto_disposition_vs_manual_queue",
    ]
    t1_savings = round((t1_minutes_saved / 60.0) * hourly_t1_cost_usd, 2)
    contain_avoidance = round(false_contain_avoided * false_contain_incident_cost_usd, 2)
    return CostAvoidanceEstimate(
        ml_only_escalated=ml_only_escalated,
        false_contain_avoided=false_contain_avoided,
        t1_minutes_saved=t1_minutes_saved,
        hourly_t1_cost_usd=hourly_t1_cost_usd,
        false_contain_incident_cost_usd=false_contain_incident_cost_usd,
        estimated_t1_savings_usd=t1_savings,
        estimated_false_contain_avoidance_usd=contain_avoidance,
        estimated_total_avoidance_usd=round(t1_savings + contain_avoidance, 2),
        notes=notes,
    )
