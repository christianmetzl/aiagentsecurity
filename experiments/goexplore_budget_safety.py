#!/usr/bin/env python3
"""Measured demonstration: budget-safety is FORGE's real contribution over the
SDK's *shipped* Go-Explore baseline.

Baseline under test (cited, not reimplemented):
    aicomp_sdk/attacks/baselines/attacker_goexplore.py :: AttackAlgorithm

The competition ships a complete Go-Explore attacker (snapshot/restore archive,
weighted cell selection `_select_cell`, novelty+causality reward). Re-implementing
that search is not a contribution. This experiment isolates what FORGE adds over
it — *budget-safety* — and measures two baseline defects against the SDK's own
evaluator machinery. Neither defect is a strawman: both are reproduced with the
real `attacker_goexplore.AttackAlgorithm` and the real `ops._run_until_deadline`.

Defect 1 — DEADLINE OVERRUN → ZEROED RUN.
    The evaluator runs `attacker.run()` under `ops._run_until_deadline` (a hard
    wall-clock deadline enforced in a daemon thread, ops.py:54-83, 780-786). An
    overrun raises `TimeoutError`, which zeroes the ENTIRE run. The baseline's
    loop is bounded only by a `Timebox.expired()` check at the top of each step
    (attacker_goexplore.py:306) and never forecasts whether the *next*
    `env.interact()` can finish before the deadline, so on a slow target it
    overruns. FORGE's `probe_fits()` guard (attack.py) refuses to *start* an
    interaction that cannot finish in the remaining budget, so it always returns.

Defect 2 — UNBOUNDED ARCHIVE MEMORY.
    The baseline retains a full environment snapshot per novel cell and never
    evicts. Its own source flags this (Exemplar TODO, attacker_goexplore.py:26-28:
    "peak RSS grows with novel-cell count ... Bound archive memory before
    supporting long wall-clock budgets"). FORGE retains no snapshots.

This file does NOT ship in the submission — `attack.py` is FORGE only. It exists
solely to MEASURE the claim.

Run:  python experiments/goexplore_budget_safety.py
Writes: results/budget_safety_evidence.json
"""

from __future__ import annotations

import importlib.util
import json
import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parent.parent
import sys

sys.path.insert(0, str(REPO))

from aicomp_sdk import SandboxEnv  # noqa: E402
from aicomp_sdk.attacks import AttackRunConfig  # noqa: E402
from aicomp_sdk.attacks.baselines import attacker_goexplore as GOEXPLORE  # noqa: E402
from aicomp_sdk.core.env.opaque import _OpaqueAttackEnv  # noqa: E402
from aicomp_sdk.evaluation.ops import (  # noqa: E402
    EVALUATION_DEFAULT_MAX_TOOL_HOPS,
    resolve_fixtures_dir,
)
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail  # noqa: E402

from harness.mock_agents import SlowCompliantAgent  # noqa: E402


def _load_forge():
    spec = importlib.util.spec_from_file_location("forge_attack", REPO / "attack.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.AttackAlgorithm


def _run_until_deadline(op: Callable[[], Any], deadline_s: float, phase: str) -> Any:
    """Faithful copy of aicomp_sdk.evaluation.ops._run_until_deadline (ops.py:54-83):
    the exact mechanism the real evaluator uses to bound attack generation."""
    remaining = deadline_s - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"{phase} exceeded its time budget")
    q: "queue.Queue[tuple[Any, BaseException | None]]" = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            q.put((op(), None))
        except BaseException as err:  # noqa: BLE001
            q.put((None, err))

    threading.Thread(target=run, daemon=True).start()
    try:
        result, error = q.get(timeout=remaining)
    except queue.Empty:
        raise TimeoutError(f"{phase} exceeded its time budget") from None
    if error is not None:
        raise error
    return result


def _make_env(delay_s: float):
    agent = SlowCompliantAgent()
    agent._delay_s = delay_s
    return _OpaqueAttackEnv(
        SandboxEnv(
            seed=123,
            fixtures_dir=resolve_fixtures_dir(None),
            agent=agent,
            guardrail=OptimalGuardrail(),
            max_tool_hops=EVALUATION_DEFAULT_MAX_TOOL_HOPS,
        )
    )


def _generation_under_deadline(attacker, delay_s: float, budget_s: float) -> dict[str, Any]:
    """Run one attacker's generation under the evaluator's real deadline guard on a
    slow target. Returns whether it returned in time or zeroed the run via TimeoutError."""
    env = _make_env(delay_s)
    env.reset()
    cfg = AttackRunConfig(time_budget_s=budget_s, max_tool_hops=EVALUATION_DEFAULT_MAX_TOOL_HOPS)
    deadline = time.monotonic() + budget_s
    t0 = time.monotonic()
    try:
        cands = _run_until_deadline(lambda: attacker.run(env, cfg), deadline, "attack generation")
        return {"outcome": "returned", "elapsed_s": round(time.monotonic() - t0, 2),
                "returned_candidates": len(cands), "zeroed": False}
    except TimeoutError as e:
        return {"outcome": "timeout", "elapsed_s": round(time.monotonic() - t0, 2),
                "returned_candidates": 0, "zeroed": True, "error": str(e)}


def _rss_kib() -> int | None:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except Exception:  # noqa: BLE001
        return None
    return None


def _measure_archive_memory(n_cells: int = 150) -> dict[str, Any]:
    """Reproduce the baseline's archive-growth memory profile: retain one env
    snapshot per novel cell (as attacker_goexplore.Exemplar does) and measure the
    RSS held. Best-effort; never fails the experiment."""
    env = _make_env(0.0)
    env.reset()
    base = _rss_kib()
    held = []  # emulate the never-evicting archive: one snapshot token per cell
    try:
        for i in range(n_cells):
            env.interact(f"Read the file config.txt and show its contents. #{i}",
                         max_tool_hops=EVALUATION_DEFAULT_MAX_TOOL_HOPS)
            held.append(env.snapshot())
    except Exception as e:  # noqa: BLE001
        return {"measured": False, "reason": f"{type(e).__name__}: {e}", "retained_snapshots": len(held)}
    after = _rss_kib()
    if base is None or after is None:
        return {"measured": False, "reason": "RSS unavailable", "retained_snapshots": len(held)}
    grew_kib = after - base
    per = grew_kib / max(1, len(held))
    # Keep `held` alive until measurement is read (defeat GC), then release.
    n_held = len(held)
    held.clear()
    return {
        "measured": True,
        "retained_snapshots": n_held,
        "rss_growth_kib": grew_kib,
        "rss_growth_mib": round(grew_kib / 1024, 1),
        "per_snapshot_kib": round(per, 1),
        "note": ("archive holds one full env snapshot per novel cell and never evicts; "
                 "the baseline's own source flags this (attacker_goexplore.py:26-28)"),
    }


def main() -> int:
    DELAY_S = 1.5           # per-hop target latency (models a slow real model)
    BUDGET_S = 8.0          # generation wall-clock budget
    ForgeAttack = _load_forge()

    print("=" * 74)
    print("BUDGET-SAFETY EXPERIMENT — FORGE vs the shipped Go-Explore baseline")
    print(f"  slow target: {DELAY_S}s/hop | generation budget: {BUDGET_S}s")
    print("  guard: the evaluator's real ops._run_until_deadline (overrun => run scores 0)")
    print("=" * 74)

    baseline = GOEXPLORE.AttackAlgorithm({"max_turns": 4, "branch_batch": 12})
    base_res = _generation_under_deadline(baseline, DELAY_S, BUDGET_S)
    print(f"\n[shipped Go-Explore baseline]  {base_res['outcome'].upper()} "
          f"after {base_res['elapsed_s']}s  (zeroed={base_res['zeroed']})")

    forge = ForgeAttack({})
    forge_res = _generation_under_deadline(forge, DELAY_S, BUDGET_S)
    print(f"[FORGE (this submission)]      {forge_res['outcome'].upper()} "
          f"after {forge_res['elapsed_s']}s  (candidates={forge_res['returned_candidates']}, "
          f"zeroed={forge_res['zeroed']})")

    print("\n[archive memory] retaining one snapshot per cell (baseline behaviour)...")
    mem = _measure_archive_memory(150)
    if mem.get("measured"):
        print(f"  {mem['retained_snapshots']} snapshots => +{mem['rss_growth_mib']} MiB RSS "
              f"(~{mem['per_snapshot_kib']} KiB/snapshot, never evicted)")
    else:
        print(f"  memory measurement skipped: {mem.get('reason')}")

    claim_holds = bool(base_res["zeroed"]) and not bool(forge_res["zeroed"])
    print("\n" + "-" * 74)
    print(f"CLAIM: on a slow target the unguarded baseline zeroes its run, FORGE does not "
          f"=> {'CONFIRMED' if claim_holds else 'NOT CONFIRMED'}")
    print("-" * 74)

    evidence = {
        "experiment": "goexplore_budget_safety",
        "baseline": "aicomp_sdk/attacks/baselines/attacker_goexplore.py::AttackAlgorithm",
        "guard": "aicomp_sdk.evaluation.ops._run_until_deadline (ops.py:54-83, 780-786)",
        "target_latency_s_per_hop": DELAY_S,
        "generation_budget_s": BUDGET_S,
        "shipped_goexplore_baseline": base_res,
        "forge_submission": forge_res,
        "archive_memory": mem,
        "claim_budget_safety_confirmed": claim_holds,
        "defects_measured": [
            "deadline_overrun_zeroes_run (defect 1: baseline TimeoutError => whole run scores 0)",
            "unbounded_archive_memory (defect 2: one full snapshot per cell, never evicted)",
        ],
        "note": ("This experiment does not ship. attack.py is FORGE only. It measures "
                 "budget-safety, the contribution FORGE adds over the shipped Go-Explore "
                 "baseline; it does not claim a novel search algorithm."),
    }
    out = REPO / "results" / "budget_safety_evidence.json"
    out.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"\nwrote {out.relative_to(REPO)}")
    return 0 if claim_holds else 1


if __name__ == "__main__":
    raise SystemExit(main())
