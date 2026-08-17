# Aegis Decision Fabric

Vendor-neutral **Detection & Remediation Engineering** — beyond agent-commoditized IaC.

Normalize alerts → composite confidence → T1–T3 triage → **Gate/Prove** decide → Action Ledger → FP/TP feedback packs.

**Beachhead adapters (GTM #1):** Snort 3 + SnortML (GID:411) + Splunk notables + OCSF `is_ml_only` / `is_corroborated`.  
**Production surface:** `POST /v1/decide` · `POST /v1/contain` · `GET /v1/ledger/{id}` (same policy as CLI).  
**Core:** open envelope — Elastic / Sentinel / SOAR / Copilot / OpenCTI labels feed the same plant.

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
| Azure Sentinel / Firepower analytics + Gate/Prove BlockIP | https://github.com/Azure/Azure-Sentinel/pull/14925 |
| Splunk SOAR dual-signal gate CF | https://github.com/phantomcyber/playbooks/pull/239 |
| Security Copilot plugin | https://github.com/Azure/Security-Copilot/pull/223 |

ADF is the **paid production consumer**. The PRs are the public bench — not free R&D forever.

## Quick start

```bash
make demo
```

```bash
python3 -m adf run fixtures/snortml_beachhead.json fixtures/splunk_notables.json fixtures/ocsf_dual_signal.json
python3 -m adf bench
python3 -m adf serve --host 127.0.0.1 --port 8080
```

## Production HTTP API

Stdlib only (`http.server`). No pip extras. Contain **defaults to SIMULATE**. ML-only is always **DENY**, even with a prove token. `ALLOW` requires `ADF_PROVE_TOKEN` and a corroborated / signature `fix_now` path.

```bash
export ADF_PROVE_TOKEN='replace-me'
export ADF_LEDGER=/var/lib/adf/action_ledger.jsonl
python3 -m adf serve --host 0.0.0.0 --port 8080
```

| Method | Path | Behavior |
|---|---|---|
| GET | `/health` | liveness |
| GET | `/openapi.yaml` | contract |
| POST | `/v1/decide` | Snort / Splunk / Sentinel / SOAR / Copilot JSON → Gate/Prove envelope |
| POST | `/v1/contain` | SIMULATE default; ALLOW needs prove token; ML-only DENY |
| GET | `/v1/ledger/{id}` | Action Ledger evidence (`ledger_id` or `alert_id`) |

```bash
curl -sS http://127.0.0.1:8080/v1/decide \
  -H 'Content-Type: application/json' \
  -d '{"gid":411,"snortml_score":0.97,"msg":"SnortML possible SQLi (ML-only)","alert_id":"ml-sqli-002"}'
```

Envelope always includes `never_equate_ml_to_signature: true` and `allow_auto_contain` (false on ML-only). Soft CTA: `consultation` → https://a2zsoc.com/consultation

```bash
docker build -t aegis-decision-fabric .
docker run --rm -p 8080:8080 \
  -e ADF_PROVE_TOKEN=replace-me \
  -v adf-data:/data \
  aegis-decision-fabric
```

## Splunk ES Gate/Prove TA (beachhead runtime)

Installable app at `splunk_app/TA-aegis-decision-fabric`. Custom alert action **ADF Gate/Prove Contain** posts notables to this fabric (`/v1/decide` then `/v1/contain`). Default **SIMULATE**. ML-only **DENY**. That is the Splunk ES cost-avoidance plane: notables do not ungated-block on SnortML GID 411.

```bash
make package-splunk   # artifacts/TA-aegis-decision-fabric.tar.gz
# copy into $SPLUNK_HOME/etc/apps/ and restart Splunk
| sendalert adf_gate_contain param.adf_url="http://adf.internal:8080" param.mode="simulate"
```

Paid SKU remains [Continuous Trust / consultation](https://a2zsoc.com/consultation) — not unpaid Splunk R&D.

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
  ingest/       SnortML + Splunk + OCSF + Sentinel + SOAR + Copilot adapters
  confidence/   composite policy
  triage/       suppress ledger + tiers
  decide/       commander decision page
  gate/         kill-switch + ML-only deny + simulate-default
  ledger/       Action Ledger (diligence)
  api.py        in-process Gate/Prove
  http_app.py   stdlib HTTP server
  cost/         ICP cost-avoidance sketch
  feedback/     Talos FP/TP packs
  bench/        public fixture metrics
splunk_app/     Splunk ES TA (alert action → ADF HTTP)
openapi.yaml    HTTP contract
Dockerfile      air-gapped-friendly image
fixtures/       beachhead + OCSF corpus
tests/          policy + pipeline + HTTP contract tests
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
