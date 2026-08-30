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
    # (filename, build, private_fraction). All builds ship the SPLIT PORTFOLIO; the two-slot hedge
    # brackets the unresolved "does public also count" question via how much of the scored prefix is
    # reserved for private-column routes:
    #   *_robust / *_aggressive / default (pf=0.30) — private-column-robust (bet: private decides).
    #   *_public_max            (pf=0.05)           — public-leaning (bet: public also counts).
    targets = [
        ("forge_submission.ipynb", "balanced", 0.30),
        ("forge_submission_robust.ipynb", "robust", 0.30),
        ("forge_submission_aggressive.ipynb", "aggressive", 0.30),
        ("forge_submission_public_max.ipynb", "aggressive", 0.05),
        # Extra robust variants for a same-day 5-slot parallel slate: a clean private_fraction
        # sweep {0.05, 0.30, 0.45} on the SAFE (low-timeout-risk) robust build so the first batch
        # both guarantees a score and isolates the private-coverage lever.
        ("forge_submission_robust_pf05.ipynb", "robust", 0.05),
        ("forge_submission_robust_pf45.ipynb", "robust", 0.45),
        # Complete the private_fraction sweep on the (reliable, non-dense) robust build. Dense
        # builds (balanced/aggressive) errored on the real eval, so all go-forward variants are
        # robust; we vary only how much of the scored prefix is reserved for the private routes.
        ("forge_submission_robust_pf15.ipynb", "robust", 0.15),
        ("forge_submission_robust_pf60.ipynb", "robust", 0.60),
        # THROUGHPUT experiment: single-message batch_size=8 (no multi-message dense → no OOM) +
        # authoritative system-channel framings, public-focused, to test the real public ceiling.
        ("forge_submission_throughput.ipynb", "throughput", 0.05),
        # COMPLIANCE experiment: adds Crescendo (multi-turn escalation) + many-shot (in-context
        # priming) as their own probed EXFILTRATION routes on top of the role-play/terse framings.
        # Non-dense, public-focused (pf=0.05) so any real-model compliance lift shows up directly
        # against the pf0.05 robust baseline (V2 = 10.935). Both levers are literature-derived.
        ("forge_submission_crescendo.ipynb", "crescendo", 0.05),
        # --- NEXT CONFIGS (ready to fire once the single-lever A/Bs report). Built on the finding
        #     that V8 THROUGHPUT (terse batch-8) = 14.9 public, our best score: the winning
        #     substrate is batch-8, so these layer the compliance levers ONTO it. ---
        # THROUGHPUT_RP: batch-8 + role-play persona carried into the batch route. One variable vs
        # `throughput` (14.9), so the delta isolates "does role-play lift the batch route".
        ("forge_submission_throughput_rp.ipynb", "throughput_rp", 0.05),
        # MAX_COMPLIANCE: every lever on the winning substrate (batch-8 + role-play-in-batch +
        # Crescendo + many-shot). Ceiling probe; read after the single-lever A/Bs.
        ("forge_submission_max_compliance.ipynb", "max_compliance", 0.05),
        # THROUGHPUT_PF30: the winning throughput recipe at a private-covering private_fraction.
        # The final score is the PRIVATE column, so this deploys our best substrate with real
        # private-route coverage (the pf lever is orthogonal to the batch substrate).
        ("forge_submission_throughput_pf30.ipynb", "throughput", 0.30),
        # GPT_OSS_MAX: batch-8 + framings MEASURED on gpt-oss-20b (Fake Over-Refusal, Quant Fever,
        # Policy Collision, refusal-suppression). Highest-confidence NEW compliance build.
        ("forge_submission_gpt_oss_max.ipynb", "gpt_oss_max", 0.05),
        # FORGERY: speculative high-ceiling bet — forged Harmony/gemma chat-template turns
        # (reported ~91% / ~90.6% ASR). Degrades to plain requests if special tokens are escaped.
        ("forge_submission_forgery.ipynb", "forgery", 0.05),
        # DENSE_SAFE: bounded multi-message packing (2 msgs x 8 = 16 posts/cand) to break the
        # ~160 single-message ceiling. May still OOM on the real eval (one-slot test).
        ("forge_submission_dense_safe.ipynb", "dense_safe", 0.05),
        # DENSE_TERSE: corrected ceiling-breaker — TERSE-only bounded dense (no verbose
        # framings, which real data showed regress compliance). The clean packing test.
        ("forge_submission_dense_terse.ipynb", "dense_terse", 0.05),
        # FORGERY_TERSE: clean test of the structural-forgery compliance wildcard (no verbose
        # framings, which regressed). The one lever that could still raise compliance.
        ("forge_submission_forgery_terse.ipynb", "forgery_terse", 0.05),
        # THROUGHPUT_RECORDS: the LB60 mechanism (distinct-record ETL batch) reverse-engineered
        # from their code -- raises posts-sustained/candidate (~9%->~37%). The LB60 floor (~58).
        ("forge_submission_throughput_records.ipynb", "throughput_records", 0.05),
        # --- OUR INNOVATIONS ON TOP OF THE LB60 FLOOR (lever model: 58 -> ~97 -> ~227) ---
        # THROUGHPUT_MAX: LB60 ETL + aggressive token minimisation (short URLs/records + hard
        # output/reasoning suppression) -> fewer tokens -> faster prefill+decode -> more candidates
        # AND higher K_eff. 38% fewer message chars, URLs 55% shorter. Lever model ~97.
        ("forge_submission_throughput_max.ipynb", "throughput_max", 0.05),
        # THROUGHPUT_HYBRID: bounded ultra-short hybrid (2 msg x 8 hops = 16 posts/cand), every token
        # minimised so context stays ~8x smaller than the max_density=16 build that OOM'd. Biggest
        # single lever (~227). One 25s prefill amortised over 16 posts. May still OOM -- one-slot test.
        ("forge_submission_throughput_hybrid.ipynb", "throughput_hybrid", 0.05),
    ]
    for fname, build, pf in targets:
        out = outdir / fname
        out.write_text(json.dumps(build_nb(build, pf), indent=1))
        print(f"wrote {out.relative_to(REPO)} (build={build}, private_fraction={pf}, "
              f"{out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
