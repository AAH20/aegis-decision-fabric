from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from adf.pipeline import run_paths, summarize_cost


def run_bench(fixtures_dir: Path, out_dir: Path) -> dict:
    paths = sorted(
        p
        for p in fixtures_dir.glob("*.json")
        if p.name != "suppress_ledger.json"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    feedback_dir = out_dir / "feedback"
    ledger_path = out_dir / "action_ledger.jsonl"
    if ledger_path.exists():
        ledger_path.unlink()
    results = run_paths(paths, feedback_dir=feedback_dir, action_ledger_path=ledger_path)

    bands = Counter(r.confidence["band"] for r in results)
    decisions = Counter(r.decision["decision"] for r in results)
    tiers = Counter(r.triage["tier"] for r in results)
    latencies = [r.latency_ms for r in results]
    cost = summarize_cost(results)

    summary = {
        "events": len(results),
        "bands": dict(bands),
        "decisions": dict(decisions),
        "tiers": dict(tiers),
        "latency_ms": {
            "p50": sorted(latencies)[len(latencies) // 2] if latencies else 0,
            "max": max(latencies) if latencies else 0,
            "mean": round(sum(latencies) / len(latencies), 3) if latencies else 0,
        },
        "cost_avoidance_illustrative_usd": cost,
        "kpi_notes": [
            "ML-only high scores escalate — never auto FIX_NOW",
            "ML-only contain tools DENY (ml_only_deny_auto_contain)",
            "Signature/corroborated high may FIX_NOW but contain defaults to SIMULATE (Gate→Prove)",
            "Action Ledger records every gate verdict for diligence",
            "FP ledger suppress → ACCEPT + talos_fp_pack",
        ],
        "commercial_cta": "https://a2zsoc.com/consultation",
    }

    (out_dir / "bench_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / "bench_results.json").write_text(
        json.dumps([r.to_dict() for r in results], indent=2) + "\n",
        encoding="utf-8",
    )
    (out_dir / "cost_avoidance.json").write_text(json.dumps(cost, indent=2) + "\n", encoding="utf-8")
    return summary
