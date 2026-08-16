from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from adf.pipeline import run_paths


def run_bench(fixtures_dir: Path, out_dir: Path) -> dict:
    paths = sorted(
        p
        for p in fixtures_dir.glob("*.json")
        if p.name != "suppress_ledger.json"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    feedback_dir = out_dir / "feedback"
    results = run_paths(paths, feedback_dir=feedback_dir)

    bands = Counter(r.confidence["band"] for r in results)
    decisions = Counter(r.decision["decision"] for r in results)
    tiers = Counter(r.triage["tier"] for r in results)
    latencies = [r.latency_ms for r in results]

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
        "kpi_notes": [
            "ML-only high scores escalate — never auto FIX_NOW",
            "Signature high band may FIX_NOW but contain defaults to SIMULATE",
            "FP ledger suppress → ACCEPT + talos_fp_pack",
        ],
    }

    (out_dir / "bench_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / "bench_results.json").write_text(
        json.dumps([r.to_dict() for r in results], indent=2) + "\n",
        encoding="utf-8",
    )
    return summary
