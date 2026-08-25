"""Local, offline re-implementation of the evaluator's attack scoring pass.

This mirrors ``aicomp_sdk.evaluation.ops.eval_attack`` closely enough to validate a
submission end-to-end without a GPU: it runs the attacker's ``run(env, config)`` in
an env with the chosen agent+guardrail, then **replays** every returned candidate in
a fresh env, evaluates the four predicates, builds findings with the same
``score_cell_signature = cell_signature(tool_events)`` key the real evaluator uses,
and scores with the SDK's own ``score_attack`` / ``score_attack_raw``.

It is intentionally faithful on the parts that determine score, and simpler on
diagnostics.  It is NOT the official scorer — the official numbers come from the
hidden GPU replay — but it lets us prove the mechanism and measure diversity/budget
behaviour against the SDK's compliant/deterministic agents and both packaged
guardrails.

Usage:
    python -m harness.local_eval --agent compliant --guardrail optimal --budget 20
"""

from __future__ import annotations

import argparse
import importlib.util
import time
from pathlib import Path
from typing import Any

from aicomp_sdk import SandboxEnv
from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks import AttackCandidate, AttackRunConfig
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.core.predicates import eval_predicates
from aicomp_sdk.evaluation.ops import (
    EVALUATION_DEFAULT_MAX_TOOL_HOPS,
    MAX_REPLAY_FINDINGS,
    PACKAGED_FIXTURES,
    _OpaqueAttackEnv,
    resolve_fixtures_dir,
)
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail
from aicomp_sdk.attacks.baselines.guardrail_rules import Guardrail as RulesGuardrail
from aicomp_sdk.scoring import score_attack, score_attack_raw

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_attack_class(attack_path: Path):
    spec = importlib.util.spec_from_file_location("submission_attack", attack_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.AttackAlgorithm


def _build_agent(name: str):
    name = (name or "compliant").lower()
    if name in ("deterministic", "vulnerable"):
        return build_agent("deterministic")
    from harness.mock_agents import build_mock

    return build_mock(name)


def _guardrail_factory(name: str):
    name = (name or "optimal").lower()
    if name in ("optimal", "public", "optimal_public"):
        return OptimalGuardrail
    if name in ("rules", "private", "strict"):
        return RulesGuardrail
    raise ValueError(f"unknown guardrail: {name}")


def run_local(
    *,
    agent_name: str = "compliant",
    guardrail_name: str = "optimal",
    budget_s: float = 20.0,
    seed: int = 123,
    attack_path: Path | None = None,
    attack_config: dict[str, Any] | None = None,
    verbose: bool = True,
) -> dict[str, Any]:
    attack_path = attack_path or (REPO_ROOT / "attack.py")
    fixtures = resolve_fixtures_dir(None)
    AttackCls = _load_attack_class(attack_path)
    guardrail_factory = _guardrail_factory(guardrail_name)

    def make_env():
        return SandboxEnv(
            seed=seed,
            fixtures_dir=fixtures,
            agent=_build_agent(agent_name),
            guardrail=guardrail_factory(),
            max_tool_hops=EVALUATION_DEFAULT_MAX_TOOL_HOPS,
        )

    # --- generation (opaque env), timed ---------------------------------------
    run_env = _OpaqueAttackEnv(make_env())
    run_env.reset()
    attacker = AttackCls(config=attack_config or {})
    t0 = time.monotonic()
    candidates = attacker.run(run_env, AttackRunConfig(
        time_budget_s=budget_s, max_tool_hops=EVALUATION_DEFAULT_MAX_TOOL_HOPS))
    gen_time = time.monotonic() - t0

    if not isinstance(candidates, list):
        raise TypeError("run() must return a list[AttackCandidate]")

    # --- replay + score (fresh env per candidate) -----------------------------
    findings: list[dict[str, Any]] = []
    t1 = time.monotonic()
    n_replayed = 0
    for idx, cand in enumerate(candidates[:MAX_REPLAY_FINDINGS]):
        if not isinstance(cand, AttackCandidate):
            raise TypeError(f"candidate[{idx}] is not an AttackCandidate")
        env = make_env()
        env.reset()
        for m in cand.user_messages:
            env.interact(m, max_tool_hops=EVALUATION_DEFAULT_MAX_TOOL_HOPS)
        trace = env.export_trace_dict()
        n_replayed += 1
        preds = eval_predicates(trace)
        if not preds:
            continue
        findings.append({
            "predicates": preds,
            "cell_signature": cell_signature(
                trace.get("tool_events", []),
                egress_data=trace.get("egress", []),
                user_messages=trace.get("user_messages", []),
            ),
            "score_cell_signature": cell_signature(trace.get("tool_events", [])),
        })
    replay_time = time.monotonic() - t1

    uniq_cells = len({
        f["score_cell_signature"]["hash"] for f in findings
        if f.get("score_cell_signature")
    })
    predicate_counts: dict[str, int] = {}
    for f in findings:
        for p in f["predicates"]:
            predicate_counts[p["predicate"]] = predicate_counts.get(p["predicate"], 0) + 1

    result = {
        "agent": agent_name,
        "guardrail": guardrail_name,
        "budget_s": budget_s,
        "returned_candidates": len(candidates),
        "replayed_candidates": n_replayed,
        "findings": len(findings),
        "unique_cells": uniq_cells,
        "predicate_counts": predicate_counts,
        "score_raw": score_attack_raw(findings),
        "score_normalized": score_attack(findings, normalize=True),
        "gen_time_s": round(gen_time, 3),
        "replay_time_s": round(replay_time, 3),
        "telemetry": getattr(attacker, "telemetry", {}),
    }
    if verbose:
        import json

        print(json.dumps({k: v for k, v in result.items() if k != "telemetry"}, indent=2))
        print("telemetry:", json.dumps(result["telemetry"], indent=2, default=str))
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Local offline scorer for FORGE.")
    ap.add_argument("--agent", default="compliant",
                    help="compliant | stubborn | deterministic")
    ap.add_argument("--guardrail", default="optimal", help="optimal | rules")
    ap.add_argument("--budget", type=float, default=20.0)
    ap.add_argument("--seed", type=int, default=123)
    ap.add_argument("--attack", default=None, help="path to attack.py")
    args = ap.parse_args()
    run_local(
        agent_name=args.agent,
        guardrail_name=args.guardrail,
        budget_s=args.budget,
        seed=args.seed,
        attack_path=Path(args.attack) if args.attack else None,
    )


if __name__ == "__main__":
    main()
