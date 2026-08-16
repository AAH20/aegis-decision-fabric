# Aegis Decision Fabric

Vendor-neutral **Detection & Remediation Engineering** — beyond agent-commoditized IaC.

Normalize alerts → composite confidence → T1–T3 triage → Gate/Prove decide → FP/TP feedback packs.

**Beachhead adapters (GTM #1):** Snort 3 + SnortML (GID:411) + Splunk notables.  
**Core:** open envelope — Elastic/Sentinel/etc. can follow without rewriting the plant.

Ancestry: [Aegis_CM_Swarm](https://github.com/AAH20/Aegis_CM_Swarm) (swarm shape).  
Commercial: [a2zsoc.com](https://a2zsoc.com) · Continuous Trust / Gate Packet / paid pilot.

## Why this exists

Cisco Talos owns engines (Snort/SnortML, ClamAV). Splunk sits under Cisco.  
Their own narrative: **ML scores ≠ signature TPs**; false positives burn agentic SOC compute.

This fabric is the missing layer: **decision-grade pages + gated remediation + Talos-ready feedback** — not another Firepower/CCIE body, not Terraform generators.

Hard rule: **never equate SnortML score alone to a signature true positive.**

## Quick start

```bash
cd oss/aegis-decision-fabric
make demo
```

```bash
python3 -m adf run fixtures/snortml_beachhead.json fixtures/splunk_notables.json
python3 -m adf bench
```

## Pipeline

```
Snort3 / SnortML / Splunk notable
        ↓
  NormalizedAlert (vendor-neutral)
        ↓
  composite_confidence (ML capped below signature band)
        ↓
  triage (FP suppress ledger · T1/T2/T3)
        ↓
  decision page (FIX_NOW | ACCEPT | ESCALATE)
        ↓
  gate (deny / simulate / allow · kill-switch)
        ↓
  feedback (talos_fp_pack · tp_candidate_note)
```

## Layout

```text
adf/
  ingest/       SnortML + Splunk adapters
  confidence/   composite policy
  triage/       suppress ledger + tiers
  decide/       commander decision page
  gate/         kill-switch + contain simulate-default
  feedback/     Talos FP/TP packs
  bench/        public fixture metrics
fixtures/       beachhead corpus
tests/          policy + pipeline tests
```

## KPI orientation (buyer)

| Metric | Intent |
|---|---|
| ML-only high → ESCALATE not FIX_NOW | Safe Max Detection |
| Signature FIX_NOW + contain SIMULATE default | No ungated blast |
| Kill-switch | Instant deny |
| FP ledger → talos_fp_pack | Content feedback loop |
| Decision latency (bench) | T1–T3 automation proof |

## Paid pilot (not free prove)

If you run Secure Firewall / SnortML / Splunk ES and want this plane under contract:

→ [a2zsoc.com/consultation](https://a2zsoc.com/consultation) · Instant Audit / Continuous Trust  

Unpaid take-homes: refuse — run `make bench` and buy a pilot.

## License

MIT
