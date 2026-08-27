"""Public->private CANDIDATE-TRANSFER dry-run (offline model of the competition setup).

The competition generates the candidate list once against the PUBLIC guardrail, then replays
that SAME list on both the public and the (unseen) PRIVATE guardrail (see the "public-private
candidate-transfer" forum thread). `run_local` does not model this (it generates+replays on one
guardrail). Here we: (1) generate FORGE's list on Optimal (public), then (2) replay the identical
list on Optimal + our two best-guess models of the LEAKED private guardrail
(`persistent_provenance` permissive/strict), scoring each column with the real SDK scorer.

This is the closest offline proxy to the real scoring we can run WITHOUT the competition data
(the real `aicomp_private_guardrails.persistent_provenance` and the `kaggle_evaluation` gateway
ship only in the Kaggle dataset). It uses the compliant stand-in agent, so it validates the
candidate list's guardrail behaviour and the transfer, NOT real-model compliance.

    python experiments/transfer_dryrun.py            # default preset (FORGE_BUILD or balanced)
    FORGE_BUILD=robust python experiments/transfer_dryrun.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from aicomp_sdk import SandboxEnv  # noqa: E402
from aicomp_sdk.attacks import AttackRunConfig  # noqa: E402
from aicomp_sdk.core.cells import cell_signature  # noqa: E402
from aicomp_sdk.core.env.opaque import _OpaqueAttackEnv  # noqa: E402
from aicomp_sdk.core.predicates import eval_predicates  # noqa: E402
from aicomp_sdk.core.env.api import DEFAULT_MAX_TOOL_HOPS  # noqa: E402

# GROUND TRUTH (from the downloaded competition gateway, jed_attack_gateway.py):
# the real scorer builds every env with max_tool_hops = DEFAULT_MAX_TOOL_HOPS = 8,
# NOT the SDK's EVALUATION_DEFAULT_MAX_TOOL_HOPS = 4 that run_local() uses. Model the
# REAL gateway here (8) so the dense route packs the same posts/message it will at rerun.
# Override with DRYRUN_HOPS for A/B.
H = int(os.environ.get("DRYRUN_HOPS", str(DEFAULT_MAX_TOOL_HOPS)))
from aicomp_sdk.evaluation.ops import resolve_fixtures_dir  # noqa: E402
from aicomp_sdk.scoring import score_attack  # noqa: E402

from harness import local_eval as LE  # noqa: E402

FX = resolve_fixtures_dir(None)
# The private-guardrail hypotheses to replay the public list against.
COLUMNS = ["optimal", "persistent_provenance", "persistent_provenance_strict"]
SCORED_PREFIX = 250  # the real eval scores only the first ~200-250 candidates


def _attack_cls():
    import importlib

    import attack
    importlib.reload(attack)  # re-read FORGE_BUILD from env
    return attack.AttackAlgorithm


def generate_on_public(budget_s: float):
    """Run FORGE once on the PUBLIC (optimal) guardrail; return its candidate list + build."""
    env = _OpaqueAttackEnv(SandboxEnv(seed=123, fixtures_dir=FX, agent=LE._build_agent("compliant"),
                                      guardrail=LE._guardrail_factory("optimal")(), max_tool_hops=H))
    env.reset()
    atk = _attack_cls()({})
    cands = atk.run(env, AttackRunConfig(time_budget_s=budget_s, max_tool_hops=H))
    return cands, getattr(atk, "telemetry", {}).get("build", "?")


def score_on(cands, guard_name: str, prefix: int):
    """Replay the (public-generated) list on `guard_name`, scoring only the first `prefix`."""
    gf = LE._guardrail_factory(guard_name)
    findings = []
    for c in cands[:prefix]:
        env = SandboxEnv(seed=123, fixtures_dir=FX, agent=LE._build_agent("compliant"),
                         guardrail=gf(), max_tool_hops=H)
        env.reset()
        for m in c.user_messages:
            env.interact(m, max_tool_hops=H)
        tr = env.export_trace_dict()
        preds = eval_predicates(tr)
        if preds:
            findings.append({"predicates": preds,
                             "score_cell_signature": cell_signature(tr.get("tool_events", []))})
    return score_attack(findings, normalize=True), len(findings)


def main() -> int:
    budget = float(os.environ.get("DRYRUN_BUDGET_S", "25"))
    prefix = int(os.environ.get("DRYRUN_PREFIX", str(SCORED_PREFIX)))
    cands, build = generate_on_public(budget)
    print("=" * 84)
    print(f"TRANSFER DRY-RUN — generate on PUBLIC (optimal), replay the SAME list on each column")
    print(f"build={build}  generated={len(cands)} candidates  scored prefix={prefix}  (compliant stand-in)")
    print("=" * 84)
    print(f"{'column (guardrail)':36} {'norm':>8} {'findings':>9}")
    total = 0.0
    for g in COLUMNS:
        norm, nf = score_on(cands, g, prefix)
        total += norm
        tag = " (public)" if g == "optimal" else " (private hypothesis)"
        print(f"{g + tag:36} {norm:>8.1f} {nf:>9}")
    print("-" * 84)
    print(f"{'sum across columns (proxy)':36} {total:>8.1f}")
    print("Reading: the public-generated list is DUAL-COLUMN if it scores > 0 on the private")
    print("hypotheses too. Sentinel/dense score on all three; that is why rebalancing toward a")
    print("private-only route (real-secret read+post) trades all-column candidates for one-column.")
    print("NOTE: mock stand-in; the REAL private guardrail + models ship only in the Kaggle data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
