# FORGE — Submission Runbook

**Goal:** turn the prepared submission into real leaderboard signal, and spend the remaining
5-submissions/day budget to learn the most. Competition closes **2026-09-01**. As of writing we
have **submitted zero times** — the single most valuable action left is to submit and get a real
number. Everything below is written to make that fast and to extract maximum signal.

> Honest framing: all our offline numbers are compliant-mock *mechanism* checks. The real score is
> gated by GPT-OSS-20B / Gemma-4 **compliance**, which we have not measured. The first real
> submission collapses most of that uncertainty. Treat submission #1 as an experiment, not a bet.

---

## 0. What to submit (priority order)

Four notebooks are prepared; all inline the same `attack.py` and differ only by env config:

| notebook | build | `private_fraction` | bet |
|---|---|---|---|
| `forge_submission_robust.ipynb` | robust (no dense, wide, ≤3-hop msgs) | 0.30 | **reliability-first**, safest floor on slow/flaky models |
| `forge_submission_public_max.ipynb` | aggressive | 0.05 | **public-leaning** hedge (bets public column also counts) |
| `forge_submission.ipynb` | balanced | 0.30 | adaptive default |
| `forge_submission_aggressive.ipynb` | aggressive (dense) | 0.30 | throughput-first, higher ceiling / lower floor |

**Day-1 recommendation:** submit **`robust`** and **`public_max`** first. Robust is the highest-floor
"does it score at all" probe; public_max brackets the scoring-rule question. Hold `aggressive` until
you know the eval finishes in time (dense = longer per-candidate replay → timeout risk on slow CPU).

---

## 1. Pre-flight (already verified in this repo)

- ✅ `attack.py` is inlined **identically** into every notebook (checked by `scripts/build_notebook.py`
  integrity print). If you ever edit `attack.py`, **re-run `python scripts/build_notebook.py`** — a
  stale notebook silently ships old code (this bit us once).
- ✅ Candidate validity is airtight: every candidate ≤32 messages, ≤2000 chars/msg, non-empty → no
  `INVALID_SUBMISSION` from shape.
- ✅ Gateway wiring matches the downloaded `jed_attack_134815` gateway: on rerun the notebook serves
  `JEDAttackInferenceServer().serve()`; `FORGE_BUILD` / `FORGE_PRIVATE_FRACTION` are set before
  `attack.py` is imported.
- ✅ `verify.py` 13/13, `pytest` 25/25.

---

## 2. Submitting on Kaggle (confirm exact UI against the competition's *Code → Submit* tab)

1. Open the competition, **Code → New Notebook** (or *Import Notebook* and upload the chosen
   `.ipynb`). Ensure **Internet = OFF** (code-competition rule).
2. **Add Data**: attach the competition dataset (provides `kaggle_evaluation`). The scoring rerun
   provides the model runtime; you do **not** need to attach the GGUF model datasets for the actual
   submission (those are only needed for *local* CPU validation — see the forum "exact model / CPU"
   thread). Confirm on the competition's data/submit instructions.
3. **Save Version → Save & Run All (Commit)**. The commit run is *not* the scored run — it just has
   to complete without a code error. (`KAGGLE_IS_COMPETITION_RERUN` is unset here, so the notebook's
   `launch.py` takes the local branch and the offline smoke cell compiles `attack.py`.)
4. Once the version is saved, open it and click **Submit to Competition**. The hidden scoring rerun
   sets `KAGGLE_IS_COMPETITION_RERUN`, serves the gateway, and drives our `attack.py`.
5. Scoring is **slow** — expect **hours** (competitors report 2–20 h; the run has a 15 h cap). Don't
   panic if it sits "pending" for a long time.

---

## 3. Reading the result

The scorer writes `submission.csv` with **four rows**:

```
Id,Score
gpt_oss_public,  <x>
gpt_oss_private, <x>
gemma_public,    <x>
gemma_private,   <x>
```

- The overview states the **final leaderboard score is the PRIVATE score** (the two `*_private`
  rows), separate from public. (Whether it's their average or something else was still unanswered on
  the forum — watch thread 712642.) So **read the `*_private` rows first.**
- Real top scores are ~**0.06–0.135**. A private score in that ballpark is competitive; a *nonzero*
  private score at all means our split-portfolio private routes are transferring.
- A **"Submission Format Error" hours after submit** historically meant a **timeout** (too many /
  too-heavy candidates). If you see it, that's the signal to drop to `robust` and/or lower
  `max_return`, not a code bug.

---

## 4. The 5-slots/day plan (learn, don't just throw darts)

Each submission is an experiment. Suggested sequencing (adapt to what you observe):

**Day 1 — "does it score, and where":**
1. `robust` (highest floor). → Does it score? What are the private rows?
2. `public_max` (tail-off, pf=0.05). → Compares public-heavy vs balanced.
3. If both scored and finished comfortably in time: `aggressive`. → Ceiling probe.

**Day 2 — "which lever moves the private column":**
- Keep the best build; vary ONE thing per slot so each result is interpretable:
  - `private_fraction` up (0.45) vs down (0.15) — does more private coverage raise the private rows?
  - If the private rows are ~0 everywhere → the private guardrail likely blocks even the deputy /
    untrusted routes; that's the trigger to revisit the guardrail model, not to tune blindly.

**Day 3 — "lock the best two":** submit your two best-scoring configs; keep them as the final
selection. Non-determinism means re-running a good config is itself worthwhile.

> One variable per submission. With only ~15 total slots before close and a noisy scorer, disciplined
> A/Bs beat random tweaks.

---

## 5. Post-submission decision tree

- **Scores nonzero, private rows > 0** → great, the mechanism transfers. Spend remaining slots
  pushing the private column (private_fraction, then the deferred densification of untrusted→action).
- **Scores nonzero public, private rows ≈ 0** → the private guardrail is blocking our private routes
  too. Re-examine the guardrail model; the untrusted→action route may need a different framing, or
  the deputy domain guess is wrong. Do NOT keep tuning throughput.
- **Submission Format Error / timeout** → too heavy. Drop to `robust`, lower `max_return`, reduce
  per-message hops (batch_size). Re-submit.
- **Errors immediately / no score** → a wiring or runtime error. Check the notebook log; the most
  likely culprits are a missing attached dataset or an import path. Fix, re-`build_notebook.py`,
  re-submit.

---

## 6. Deferred improvements (only worth doing once real signal says so)

From the hostile-panel review, held back deliberately because they're unvalidatable offline and
trade against reliability:
- **Repeated-draw probing** — probe each firing framing k times, rank by consistency, not first-fire
  (reliability vs the non-deterministic models).
- **Densify untrusted→action** — interleave web re-reads (`web, post, post, web, …`) for ~5–8× more
  `UNTRUSTED_TO_ACTION` events per candidate (raises the private column *if* the model sustains the
  longer chain — a real reliability tradeoff).
- **Harden the private routes' `web.open` framing** and gate it on a probe.

Pick these up **after** submission #1 tells us whether reliability or private-coverage is the binding
constraint — spending the last days optimizing a mock number we can't see is the trap to avoid.
