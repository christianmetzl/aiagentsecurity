#!/usr/bin/env python3
"""Density-packing ablation: dense ON (default) vs OFF (wide fill), across stand-in targets
and both packaged guardrails, at a fixed budget. Writes results/dense_ablation.json.

Every row reports raw/normalized score, the chosen posts-per-candidate, and the measured
replay time vs budget (budget-safety: replay_s and gen_s MUST be < budget, else the real
evaluator would raise TimeoutError and zero the run). These are MECHANISM numbers against a
near-zero-latency compliant stand-in -- not real-model leaderboard scores; the absolute
lift is latency-bound (see WORKING_NOTE 3.2)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from harness import local_eval as LE  # noqa: E402

BUDGET = 30


def _row(agent: str, guard: str) -> dict:
    out = {"target": agent, "guardrail": guard, "budget_s": BUDGET}
    for key, cfg in (("dense_on", {}), ("dense_off", {"enable_dense": False})):
        r = LE.run_local(agent_name=agent, guardrail_name=guard, budget_s=BUDGET,
                         seed=123, attack_config=cfg, verbose=False)
        out[key] = {
            "returned_candidates": r["returned_candidates"],
            "raw": round(r["score_raw"], 1),
            "norm": round(r["score_normalized"], 1),
            "posts_per_candidate": r["telemetry"].get("dense_posts_per_candidate", 1),
            "gen_time_s": r["gen_time_s"],
            "replay_time_s": r["replay_time_s"],
            "budget_safe": bool(r["replay_time_s"] < BUDGET and r["gen_time_s"] < BUDGET),
        }
    on, off = out["dense_on"], out["dense_off"]
    out["raw_multiplier"] = round(on["raw"] / off["raw"], 2) if off["raw"] > 0 else None
    return out


def main() -> int:
    combos = [
        ("compliant", "optimal"), ("stubborn", "optimal"),
        ("multicall_reject", "optimal"), ("slow", "optimal"),
        ("null", "optimal"), ("compliant", "rules"),
    ]
    rows = [_row(a, g) for a, g in combos]
    all_safe = all(r["dense_on"]["budget_safe"] and r["dense_off"]["budget_safe"] for r in rows)
    out = {
        "experiment": "dense_ablation",
        "note": ("Mechanism numbers vs a compliant stand-in (near-zero latency); absolute "
                 "lift is latency-bound. dense_on is the shipped default; dense_off is the "
                 "wide one-event-per-candidate fill. All rows must be budget_safe."),
        "budget_s": BUDGET,
        "all_budget_safe": all_safe,
        "rows": rows,
    }
    (REPO / "results" / "dense_ablation.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"{'target':>16} {'guard':>8} {'off_norm':>8} {'on_norm':>8} {'x':>6} {'p/c':>4} {'safe':>5}")
    for r in rows:
        on, off = r["dense_on"], r["dense_off"]
        print(f"{r['target']:>16} {r['guardrail']:>8} {off['norm']:>8.1f} {on['norm']:>8.1f} "
              f"{str(r['raw_multiplier']):>6} {str(on['posts_per_candidate']):>4} "
              f"{'OK' if on['budget_safe'] else 'OVER':>5}")
    print(f"\nall budget-safe: {all_safe}")
    print("wrote results/dense_ablation.json")
    return 0 if all_safe else 1


if __name__ == "__main__":
    raise SystemExit(main())
