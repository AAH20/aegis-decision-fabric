from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class SignalClass(str, Enum):
    SIGNATURE = "signature"
    ML = "ml"
    SIEM_NOTABLE = "siem_notable"
    COMPOSITE = "composite"


class Disposition(str, Enum):
    SUPPRESS_FP = "suppress_fp"
    TRIAGE = "triage"
    FIX_NOW = "fix_now"
    ACCEPT = "accept"
    ESCALATE = "escalate"


class GateMode(str, Enum):
    DENY = "deny"
    SIMULATE = "simulate"
    ALLOW = "allow"


@dataclass
class NormalizedAlert:
    """Vendor-neutral detection envelope (beachhead: SnortML + Splunk; OCSF-aligned)."""

    alert_id: str
    source: str
    title: str
    signal_class: SignalClass
    severity: str = "medium"
    ml_score: float | None = None
    signature_id: str | None = None
    gid: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    is_ml_only: bool = False
    is_corroborated: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["signal_class"] = self.signal_class.value
        return d


@dataclass
class ConfidenceResult:
    alert_id: str
    composite: float
    band: str
    rationale: list[str]
    never_equate_ml_to_signature: bool = True
    is_ml_only: bool = False
    is_corroborated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TriageResult:
    alert_id: str
    disposition: Disposition
    tier: str
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["disposition"] = self.disposition.value
        return d


@dataclass
class DecisionPage:
    alert_id: str
    decision: Disposition
    composite: float
    band: str
    actions: list[str]
    evidence: list[str]
    is_ml_only: bool = False
    is_corroborated: bool = False
    deny_auto_contain: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d


@dataclass
class GateVerdict:
    tool: str
    mode: GateMode
    allowed: bool
    reason: str
    alert_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["mode"] = self.mode.value
        return d


@dataclass
class CostAvoidanceEstimate:
    """ICP-facing cost/ROI sketch for Continuous Trust conversations (not a quote)."""

    ml_only_escalated: int
    false_contain_avoided: int
    t1_minutes_saved: float
    hourly_t1_cost_usd: float
    false_contain_incident_cost_usd: float
    estimated_t1_savings_usd: float
    estimated_false_contain_avoidance_usd: float
    estimated_total_avoidance_usd: float
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
