#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adf.api import default_app
from adf.bench import run_bench
from adf.gate import set_kill_switch
from adf.http_app import serve
from adf.pipeline import run_paths, summarize_cost


def main() -> int:
    p = argparse.ArgumentParser(description="Aegis Decision Fabric — Detection & Remediation CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="Run pipeline on fixture JSON files")
    run_p.add_argument("fixtures", nargs="+", type=Path)
    run_p.add_argument("--feedback-dir", type=Path, default=ROOT / "artifacts" / "feedback")
    run_p.add_argument(
        "--action-ledger",
        type=Path,
        default=ROOT / "artifacts" / "action_ledger.jsonl",
    )
    run_p.add_argument("--kill-switch", action="store_true")
    run_p.add_argument("--json", action="store_true")

    bench_p = sub.add_parser("bench", help="Run public fixture benchmark + cost sketch")
    bench_p.add_argument("--fixtures-dir", type=Path, default=ROOT / "fixtures")
    bench_p.add_argument("--out-dir", type=Path, default=ROOT / "artifacts" / "bench")

    serve_p = sub.add_parser("serve", help="HTTP Gate/Prove API (stdlib; SIMULATE default)")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8080)
    serve_p.add_argument(
        "--ledger",
        type=Path,
        default=None,
        help="Action Ledger JSONL path (or ADF_LEDGER)",
    )

    args = p.parse_args()

    if args.cmd == "run":
        if args.kill_switch:
            set_kill_switch(True)
        if args.action_ledger.exists():
            args.action_ledger.unlink()
        results = run_paths(
            args.fixtures,
            feedback_dir=args.feedback_dir,
            action_ledger_path=args.action_ledger,
        )
        payload = [r.to_dict() for r in results]
        cost = summarize_cost(results)
        if args.json:
            print(json.dumps({"results": payload, "cost_avoidance_illustrative_usd": cost}, indent=2))
        else:
            for r in results:
                d = r.decision
                g = r.gate or {}
                print(
                    f"{r.alert_id:20s} band={r.confidence['band']:6s} "
                    f"tier={r.triage['tier']:2s} decision={d['decision']:10s} "
                    f"ml_only={str(d.get('is_ml_only')):5s} "
                    f"gate={g.get('reason', '-'):40s} "
                    f"composite={r.confidence['composite']:.3f} {r.latency_ms:.2f}ms"
                )
            print(
                f"\nillustrative cost avoidance USD: "
                f"{cost['estimated_total_avoidance_usd']} "
                f"(T1 {cost['estimated_t1_savings_usd']} + "
                f"false-contain {cost['estimated_false_contain_avoidance_usd']})"
            )
            print("Continuous Trust / paid pilot → https://a2zsoc.com/consultation")
        return 0

    if args.cmd == "bench":
        summary = run_bench(args.fixtures_dir, args.out_dir)
        print(json.dumps(summary, indent=2))
        print(f"wrote {args.out_dir}")
        return 0

    if args.cmd == "serve":
        serve(host=args.host, port=args.port, app=default_app(args.ledger))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
