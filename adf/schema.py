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
    """Vendor-neutral detection envelope (beachhead: SnortML + Splunk)."""

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

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["mode"] = self.mode.value
        return d
