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

This notebook writes `attack.py` (an `AttackAlgorithm` subclass) and serves the JED attack
inference gateway that the competition evaluator connects to on rerun. Build preset:
**`{build}`** (set via `FORGE_BUILD`).

**Method — live validation-fill.** `run()` is invoked once per target model against that
model's live env. It generates one single-message candidate, replays it, and *keeps it only
if the target actually fired the scored predicate* — repeating until a replay-safe cushion.
Every returned candidate provably fired, so 100% of the scored list contributes, and the
loop self-sizes to each model's real speed. A per-model latency split routes the reasoning
row (gpt_oss / Harmony) through a chain-of-thought-suppression template for a faster fill.
Verified against `aicomp_sdk` 3.1.2 (scoring / predicates / guardrail) and offline mocks.
"""


LAUNCH = f"""%%writefile launch.py
import sys, os, glob
from pathlib import Path

# Select the FORGE build preset (see attack.py _Config._BUILD_PRESETS). Set BEFORE the
# server imports/loads attack.py so _Config reads it.
os.environ.setdefault("FORGE_BUILD", "__BUILD__")
# Private-column coverage: fraction of the scored prefix reserved for the split-portfolio's
# private routes (untrusted->action + whitelisted-domain deputy). ~0.30 is the private-robust
# default; the public_max hedge lowers it to bet the public column also counts. See §0.1.
os.environ.setdefault("FORGE_PRIVATE_FRACTION", "__PF__")

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
elif os.getenv("FORGE_LOCAL_GATEWAY"):
    # OPT-IN local validation only -- requires the model GGUF datasets attached (see the
    # "confirmation of exact model and CPU or GPU" thread for the CPU llama-cpp recipe).
    attack_srv.JEDAttackInferenceServer().run_local_gateway()
else:
    # Plain commit run (Save & Run All): do NOT drive the local gateway -- it needs the models,
    # and this would error/hang and block the commit. attack.py is already written and compiled
    # by the smoke cell; that is all the commit needs. The scored SUBMIT rerun sets
    # KAGGLE_IS_COMPETITION_RERUN and serves the gateway above. Attach the model datasets and set
    # FORGE_LOCAL_GATEWAY=1 if you want to run a full local validation here.
    print("Commit run OK: attack.py + launch.py written; attack.py compiles. "
          "Submit this version -- the scored rerun will serve the gateway. "
          "(Set FORGE_LOCAL_GATEWAY=1 with model datasets attached for local validation.)")
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


def build_nb(build: str, private_fraction: float = 0.30) -> dict:
    launch = LAUNCH.replace("__BUILD__", build).replace("__PF__", f"{private_fraction:g}")
    return {
        "cells": [
            md_cell(intro(build)),
            code_cell("%%writefile attack.py\n" + ATTACK),
            code_cell(launch),
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
    # (filename, build, private_fraction). The two FINAL-SELECTION submissions run the
    # field-converged live validation-fill (attack.py `strategy=validation_fill`). Kaggle scores
    # the PRIVATE column on the BETTER of your two selected finals, so A + B is a free hedge on the
    # one unknown that decides the competition — whether the private guardrail inspects the
    # http.post `data` sink:
    #   * public_max    (Final A) — 100% single-post SECRET_MARKER exfil. Verified vs the SDK and
    #                   three MIT-licensed competitor notebooks; the ~80-147 public regime. Also
    #                   wins private IF the private guardrail allows marker-in-data exfil.
    #   * private_hedge (Final B) — mixed exfil + CONFUSED_DEPUTY. Marker-exfil is blocked by any
    #                   data-inspecting private guardrail (measured: the SDK `rules` baseline zeroes
    #                   it), but email.send-without-intent carries no secret pattern and survives —
    #                   demonstrated on `rules`. Wins private IF the private guardrail blocks exfil.
    # FORGE_PRIVATE_FRACTION is inert for the validation-fill path (kept for the legacy builds).
    targets = [
        # Today's finals-hunt slate (5). Two Final-A (public) candidates, two Final-B (private)
        # candidates, one diagnostic — each isolates one variable so tomorrow we select the best 2.
        ("forge_submission_public_max.ipynb", "public_max", 0.05),          # Final A — floor, aim 180
        ("forge_submission_deputy_max.ipynb", "deputy_max", 0.05),          # Final B — pure private survivor
        ("forge_submission_ceiling_breaker.ipynb", "ceiling_breaker", 0.05),# Final A upside — >180 swing
        ("forge_submission_private_hedge.ipynb", "private_hedge", 0.05),    # Final B — mixed (deputy-underfire safe)
        ("forge_submission_public_max_nosplit.ipynb", "public_max_nosplit", 0.05),  # diagnostic — forge A/B
        # Tomorrow's ready-to-fire public retunes (all gateway-grounded):
        ("forge_submission_public_max_099.ipynb", "public_max_099", 0.05),        # frac 0.99 (safe +1-2%)
        ("forge_submission_public_max_flood.ipynb", "public_max_flood", 0.05),    # flood to 2000 (safe, >=86)
        ("forge_submission_public_max_terse.ipynb", "public_max_terse", 0.05),    # terser msg -> lower replay cost (swing)
        # THE INNOVATION — parser-safe hop-chain multipost (above the single-post ceilings):
        ("forge_submission_public_hopchain.ipynb", "public_hopchain", 0.05),      # exfil hop-chain -> beat public (86->130+)
        ("forge_submission_deputy_hopchain.ipynb", "deputy_hopchain", 0.05),      # deputy hop-chain -> WIN private (20->100+)
    ]
    for fname, build, pf in targets:
        out = outdir / fname
        out.write_text(json.dumps(build_nb(build, pf), indent=1))
        print(f"wrote {out.relative_to(REPO)} (build={build}, private_fraction={pf}, "
              f"{out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
