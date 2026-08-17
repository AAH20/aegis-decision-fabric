# TA-aegis-decision-fabric

Splunk ES / Splunk Enterprise **custom alert action** that sends notables to [Aegis Decision Fabric](https://github.com/AAH20/aegis-decision-fabric) Gate/Prove HTTP:

`POST /v1/decide` then `POST /v1/contain`

**Hard rule:** ML confidence is never a signature true positive. Contain **defaults to SIMULATE**. ML-only is always **DENY**, even with a prove token.

Paid Continuous Trust / consultation: https://a2zsoc.com/consultation

## Install

1. Run ADF: `python3 -m adf serve --host 0.0.0.0 --port 8080`
2. Copy this app to `$SPLUNK_HOME/etc/apps/TA-aegis-decision-fabric` (or `make package-splunk` and install the tarball)
3. Restart Splunk
4. On a notable / saved search: **Add Actions → ADF Gate/Prove Contain**

```
| sendalert adf_gate_contain param.adf_url="http://adf.internal:8080" param.mode="simulate"
```

Attach to the dual-signal ESCU searches (SnortML GID 411 vs signature + EVE corroboration) once [security_content#4221](https://github.com/splunk/security_content/pull/4221) lands. Pair with SOAR [playbooks#239](https://github.com/phantomcyber/playbooks/pull/239) for `block ip` inside Phantom.

## Parameters

| Param | Default | Meaning |
|---|---|---|
| `adf_url` | `http://127.0.0.1:8080` | ADF HTTP origin |
| `adapter` | `splunk` | `splunk` / `snort` / `sentinel` / `auto` |
| `tool` | `block_ip` | Contain tool name ADF will gate |
| `mode` | `simulate` | `allow` still needs prove token; ML-only stays DENY |
| `prove_token` | empty | Maps to `ADF_PROVE_TOKEN` |

## Cost this cuts

Ungated `block ip` / FMC quarantine on SnortML-only notables. T1 minutes spent treating "high ML" as a signature true positive.

Package for Splunkbase / offline install:

```bash
make package-splunk
```
