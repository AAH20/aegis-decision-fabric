# Aegis Decision Fabric

Vendor-neutral **Detection & Remediation Engineering** — beyond agent-commoditized IaC.

Normalize alerts → composite confidence → T1–T3 triage → **Gate/Prove** decide → Action Ledger → FP/TP feedback packs.

**Beachhead adapters (GTM #1):** Snort 3 + SnortML (GID:411) + Splunk notables + OCSF `is_ml_only` / `is_corroborated`.  
**Core:** open envelope — Elastic / Sentinel / OpenCTI labels can feed the same plant.

Ancestry: [Aegis_CM_Swarm](https://github.com/AAH20/Aegis_CM_Swarm).  
**Commercial (how this is sold):** [Continuous Trust / consultation](https://a2zsoc.com/consultation) on [a2zsoc.com](https://a2zsoc.com).

## Why this exists (revenue + cost)

SOC ICPs do not pay for “more alerts.” They pay to **cut T1–T3 burn** and **avoid false containment** when agentic tooling treats ML probability as a signature true positive.

| Cost driver | What ADF does | Buyer outcome |
|---|---|---|
| T1 queue minutes on flat “high confidence” | Auto disposition + escalate ML-only | Fewer analyst hours |
| Wrong BlockIP / quarantine from SnortML-only | **DENY** contain tools (`ml_only_deny_auto_contain`) | Incident cost avoidance |
| Ungated “AI remediate” risk | Gate→Prove + kill-switch + Action Ledger | Diligence-ready ops |
| Content feedback to vendors | `talos_fp_pack` / TP notes | Closed loop with Talos/SIEM teams |

Hard rule: **never equate ML score alone to a signature true positive.**

Illustrative cost sketch (defaults, **not a quote**): run `make bench` → `artifacts/bench/cost_avoidance.json`.

## Public proof pack (portable sisters)

These open contributions encode the same dual-signal doctrine ADF consumes in production:

| Surface | Link |
|---|---|
| EvidenceForge corpus | https://github.com/Cisco-Talos/EvidenceForge/pull/389 |
| Splunk ESCU | https://github.com/splunk/security_content/issues/4220 |
| Sigma | https://github.com/SigmaHQ/sigma/pull/6237 |
| Elastic detection-rules | https://github.com/elastic/detection-rules/pull/6662 |
| OCSF schema | https://github.com/ocsf/ocsf-schema/pull/1732 |
| OpenCTI connector | https://github.com/OpenCTI-Platform/connectors/pull/7298 |
| Azure Sentinel / Firepower | https://github.com/Azure/Azure-Sentinel/pull/14925 |

ADF is the **paid production consumer**. The PRs are the public bench — not free R&D forever.

## Quick start

```bash
make demo
```

```bash
python3 -m adf run fixtures/snortml_beachhead.json fixtures/splunk_notables.json fixtures/ocsf_dual_signal.json
python3 -m adf bench
```

## Pipeline

```
Snort3 / SnortML / Splunk / OCSF finding
        ↓
  NormalizedAlert (is_ml_only · is_corroborated)
        ↓
  composite_confidence (ML capped; corroborated elevated)
        ↓
  triage (FP suppress ledger · T1/T2/T3)
        ↓
  decision page (FIX_NOW | ACCEPT | ESCALATE)
        ↓
  gate (DENY ml-only contain · SIMULATE default · kill-switch)
        ↓
  Action Ledger (append-only Gate/Prove audit)
        ↓
  feedback (talos_fp_pack · tp_candidate_note)
```

## Layout

```text
adf/
  ingest/       SnortML + Splunk + OCSF adapters
  confidence/   composite policy
  triage/       suppress ledger + tiers
  decide/       commander decision page
  gate/         kill-switch + ML-only deny + simulate-default
  ledger/       Action Ledger (diligence)
  cost/         ICP cost-avoidance sketch
  feedback/     Talos FP/TP packs
  bench/        public fixture metrics
fixtures/       beachhead + OCSF corpus
tests/          policy + pipeline tests
```

## KPI orientation (buyer)

| Metric | Intent |
|---|---|
| ML-only high → ESCALATE + contain DENY | Safe Max Detection |
| Signature / corroborated FIX_NOW + contain SIMULATE | Gate→Prove (no ungated blast) |
| Kill-switch | Instant deny |
| Action Ledger | Diligence / SOW evidence |
| FP ledger → talos_fp_pack | Content feedback loop |
| Decision latency (bench) | T1–T3 automation proof |

## Paid pilot (not free prove)

If you run Secure Firewall / SnortML / Splunk ES / Sentinel Firepower and want this plane under contract:

→ **[a2zsoc.com/consultation](https://a2zsoc.com/consultation)** · Instant Audit / Continuous Trust / Gate Packet

Unpaid take-homes: refuse — run `make bench` and buy a pilot.

## License

MIT
