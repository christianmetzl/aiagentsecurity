#!/usr/bin/env python3
"""Generate the Kaggle submission notebooks from attack.py (single source of truth).

Each notebook (1) writes ``attack.py`` into the working dir, (2) writes a ``launch.py``
that serves the JED attack inference gateway the competition rerun connects to — the
VERIFIED submission pattern (a file-write-only notebook does not score) — and (3) runs it.
A build preset is selected via the ``FORGE_BUILD`` env var set inside launch.py, so one
attack.py backs all builds:

    balanced   — the adaptive default.
    robust     — reliability-first (wide single-post, tight best-first cap): highest floor
                 on the slow-CPU, malformed-JSON, ~250-scored-candidate real evaluator.
    aggressive — throughput-first (moderate density/batching): higher ceiling, lower floor.

Scoring on the real eval is non-deterministic, so submit the two hedge builds across the
5/day budget. Re-run after editing attack.py so the notebooks never drift.

    python scripts/build_notebook.py
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ATTACK = (REPO / "attack.py").read_text()
COMP_ID = 134815  # competition id -> kaggle_evaluation.jed_attack_134815


def code_cell(src: str) -> dict:
    return {"cell_type": "code", "metadata": {}, "execution_count": None,
            "outputs": [], "source": src.splitlines(keepends=True)}


def md_cell(src: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": src.splitlines(keepends=True)}


def intro(build: str) -> str:
    return f"""# FORGE — Multi-Step Tool-Attack Search (submission: `{build}`)

**Fingerprint-Oriented Replay-Guided Exploration.** This notebook writes `attack.py`
(an `AttackAlgorithm` subclass) and serves the JED attack inference gateway that the
competition evaluator connects to on rerun. Build preset: **`{build}`** (set via
`FORGE_BUILD`). FORGE probes the live guardrail during generation and specialises to it;
the returned candidate list is sized to fit the replay budget and ordered best-first
(the evaluator scores only the first ~200-250 candidates).
"""


LAUNCH = f"""%%writefile launch.py
import sys, os, glob
from pathlib import Path

# Select the FORGE build preset (see attack.py _Config._BUILD_PRESETS). Set BEFORE the
# server imports/loads attack.py so _Config reads it.
os.environ.setdefault("FORGE_BUILD", "__BUILD__")

sys.argv = [sys.argv[0]]

# Make the competition's kaggle_evaluation package importable (it ships in the attached
# competition dataset under /kaggle/input/**/kaggle_evaluation).
for candidate in glob.glob("/kaggle/input/**/kaggle_evaluation", recursive=True):
    root = str(Path(candidate).parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    print("kaggle_evaluation root:", root)
    break

import kaggle_evaluation.jed_attack_{COMP_ID}.jed_attack_inference_server as attack_srv

if os.getenv("KAGGLE_IS_COMPETITION_RERUN"):
    # Competition scoring: the external JED gateway connects and drives our attack.py.
    attack_srv.JEDAttackInferenceServer().serve()
else:
    # Interactive/local validation (requires the model + wheelhouse datasets; see the
    # "confirmation of exact model and CPU or GPU" discussion thread for the CPU recipe).
    attack_srv.JEDAttackInferenceServer().run_local_gateway()
"""


SMOKE = '''# Optional offline sanity check (skipped during the competition rerun): compile attack.py
# so a syntax error fails loudly here rather than at the hidden scorer. No SDK / GPU needed.
import os, py_compile
if not os.getenv("KAGGLE_IS_COMPETITION_RERUN"):
    py_compile.compile("attack.py", doraise=True)
    print("OK: attack.py compiles. FORGE_BUILD preset is set inside launch.py.")
'''

RUN = '''# Serve the gateway. On the competition rerun this connects to the external JED gateway
# and is scored; run it on a CPU kernel with the model datasets attached to validate locally.
!python launch.py
'''


def build_nb(build: str) -> dict:
    return {
        "cells": [
            md_cell(intro(build)),
            code_cell("%%writefile attack.py\n" + ATTACK),
            code_cell(LAUNCH.replace("__BUILD__", build)),
            code_cell(SMOKE),
            code_cell(RUN),
        ],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
        },
        "nbformat": 4, "nbformat_minor": 5,
    }


def main() -> None:
    outdir = REPO / "notebook"
    targets = {
        "forge_submission.ipynb": "balanced",
        "forge_submission_robust.ipynb": "robust",
        "forge_submission_aggressive.ipynb": "aggressive",
    }
    for fname, build in targets.items():
        out = outdir / fname
        out.write_text(json.dumps(build_nb(build), indent=1))
        print(f"wrote {out.relative_to(REPO)} (build={build}, {out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
