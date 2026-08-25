#!/usr/bin/env python3
"""Generate the Kaggle submission notebook from attack.py (single source of truth).

The notebook writes attack.py into /kaggle/working/ (which the evaluator loads) and
runs a fast, offline smoke test so a committed notebook fails loudly if the file is
malformed — before it ever reaches the hidden GPU scorer.

    python scripts/build_notebook.py

Re-run after editing attack.py so the notebook never drifts from the source.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ATTACK = (REPO / "attack.py").read_text()


def code_cell(src: str) -> dict:
    return {"cell_type": "code", "metadata": {}, "execution_count": None,
            "outputs": [], "source": src.splitlines(keepends=True)}


def md_cell(src: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": src.splitlines(keepends=True)}


INTRO = """# FORGE — Multi-Step Tool-Attack Search (Submission)

**Fingerprint-Oriented Replay-Guided Exploration.**

This notebook writes `attack.py` (an `AttackAlgorithm` subclass) to the working
directory; the competition evaluator loads it, runs `run(env, config)` against the
target agents (GPT-OSS-20B, Gemma-4), and replays the returned candidates to score
them against the four security predicates.

FORGE **probes the live guardrail during generation** and specialises to it: on the
permissive public guardrail it drives `http.post` of a payload carrying the
`SECRET_MARKER` sentinel (EXFILTRATION); on a stricter guardrail that blocks the
marker it adapts to a read-`secret.txt`-then-post-the-real-value chain; and it always
carries an unintended-`email.send` route (CONFUSED_DEPUTY). A bounded **batch-exfil**
route stacks several `http.post` calls in one interaction to maximise severity per
unit of replay compute. The returned list is sized so replay provably fits its
budget, and every candidate is validated against the harness limits.
"""

WRITE = "%%writefile attack.py\n" + ATTACK

SMOKE = '''# Fast offline smoke test: load attack.py, run against the SDK's deterministic
# agent, and confirm it returns a valid, replayable candidate list. This does NOT
# use a GPU and does NOT reflect real-model scores; it only proves the file loads
# and honours the contract before the hidden scorer runs.
import importlib.util, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("attack", "attack.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

from aicomp_sdk import SandboxEnv
from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks import AttackCandidate, AttackRunConfig
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail
from aicomp_sdk.core.env.opaque import _OpaqueAttackEnv
import aicomp_sdk.evaluation.ops as ops

fixtures = ops.resolve_fixtures_dir(None)
env = _OpaqueAttackEnv(SandboxEnv(seed=123, fixtures_dir=fixtures,
        agent=build_agent("deterministic"), guardrail=OptimalGuardrail(),
        max_tool_hops=ops.EVALUATION_DEFAULT_MAX_TOOL_HOPS))
env.reset()
cands = mod.AttackAlgorithm({}).run(env, AttackRunConfig(
        time_budget_s=8, max_tool_hops=ops.EVALUATION_DEFAULT_MAX_TOOL_HOPS))

assert isinstance(cands, list) and cands, "run() must return a non-empty list"
assert len(cands) <= mod.MAX_CANDIDATES
for c in cands:
    assert isinstance(c, AttackCandidate)
    msgs = list(c.user_messages)
    assert 1 <= len(msgs) <= mod.MAX_MESSAGES_PER_CANDIDATE
    for m in msgs:
        assert isinstance(m, str) and m.strip() and len(m) <= mod.MAX_USER_MESSAGE_CHARS
print(f"OK: attack.py loaded and returned {len(cands)} valid candidates.")
print("telemetry:", getattr(mod.AttackAlgorithm({}), "telemetry", {}))
'''

nb = {
    "cells": [md_cell(INTRO), code_cell(WRITE), code_cell(SMOKE)],
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4, "nbformat_minor": 5,
}

out = REPO / "notebook" / "forge_submission.ipynb"
out.write_text(json.dumps(nb, indent=1))
print(f"wrote {out} ({out.stat().st_size} bytes)")
