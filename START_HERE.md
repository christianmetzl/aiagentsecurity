# START HERE — reviewer path

FORGE — an attack for *AI Agent Security: Multi-Step Tool Attacks* (Kaggle, 2026), plus a matched
defense and a working note. This page gets you from curiosity to a reproduced result in minutes.

## 1. Reproduce the core claims (offline, no GPU, no network, no credentials)

```bash
python verify.py --fast     # fast lane (~3 min, 12/12 checks): mechanism + defense
python verify.py            # full lane: adds the larger scaling check
python -m pytest -q         # the complete test suite (27 tests, ~7 min)
```

`verify.py` prints an explicit **N/N PASS** line and *asserts* (it does not merely print). It mixes
**re-execution** checks (actually run generation + replay and assert the score) and **evidence-audit**
checks (candidate validity, harness limits, guardrail closure), per the verification discipline.

## 2. The 3-minute tour of the claims

| To see… | Open |
|---|---|
| The scoring reverse-engineering + the whole argument | **`docs/paper/forge_working_note.pdf`** (or `.docx`, or `docs/paper/KAGGLE_WRITEUP.md`) |
| Every public claim → script → evidence → tier → status | **`docs/CLAIMS_LEDGER.md`** |
| Predictions committed *before* the data (incl. final-selection + private-column) | **`docs/PREREGISTRATION.md`** |
| Answers to every likely objection, with evidence pointers | **`docs/ANTICIPATED_OBJECTIONS.md`** |
| The real-eval scores, incl. the measured **negative** results | **`results/real_submissions_log.md`** |
| The attack (single source of truth for all notebooks) | **`attack.py`** |
| The matched defense (guardrail + input sanitizer) | **`defense/forge_guardrail.py`**, `defense/template_sanitizer.py` |

## 3. The one-paragraph result

Score ≈ `0.09 × (tool calls that fire)` — a time-bounded linear knapsack (derived from the gateway
source + a competitor solution). The binding constraint is **candidate throughput × posts-sustained**,
not model refusal. **Measured:** a terse batch-8 build scores **14.915** public; every "smarter"
addition we tried (ETL+token-min, role-play, Crescendo/many-shot) **regressed** it — the simplest build
wins. The matched, prompt-agnostic defense drives our strongest attacks to **0** with no benign false
positives. Every number is tagged **[measured] / [inferred] / [speculative]** and traces to a committed
artifact. This is defensive research on a **sandboxed** benchmark with synthetic markers; the one
guardrail gap we exploit is disclosed to the organizers with a fix.

## 4. Ethics & scope

Synthetic secret (`SECRET_MARKER`), reserved `*.invalid`/`*.example` destinations, no real target.
Bug 1 (the `OptimalGuardrail` data-channel gap) is documented in the claims ledger and ships with a
fixed reference guardrail in `defense/`.
