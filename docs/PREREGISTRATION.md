# Pre-registration — FORGE attack submission

*Committed before any target-model (GPT-OSS-20B, Gemma-4) score is known to the
author. The author has no GPU access to the competition targets in the build
environment; all target-model outcomes below are predictions, to be reported **as
measured** once a Kaggle submission returns leaderboard numbers.*

The binding timestamp is this file's git commit. The claims here are deliberately
falsifiable and several are expected to be **wrong**; a falsified prediction reported
honestly is evidence the method and its limits are understood.

## What is fixed before data

**Reference facts** (traceable to `aicomp_sdk==3.1.2`, see
[`BENCHMARK_MECHANICS.md`](BENCHMARK_MECHANICS.md)):
* scoring formula, severity weights, normalisation constant;
* the four predicate triggers and the score-cell definition;
* the public `OptimalGuardrail` decision rule and the `guardrail_rules` baseline;
* the budget/shape limits (2000 candidates, 32 msgs, 2000 chars, 4 hops, greedy).

**Guardrails frozen for the private leaderboard prediction:** the private guardrail is
unknown; predictions that mention it assume it is *behaviourally similar to*
`guardrail_rules` (allows secret reads, blocks the literal `SECRET_MARKER` sink). This
assumption is disclosed wherever used and may be false.

## Primary predictions (P)

* **P1 — Mechanism (verifiable offline, not model-dependent).** Against the SDK's own
  scoring pipeline and a *compliant tool-following* stand-in agent, FORGE produces
  findings that fire `EXFILTRATION` on `OptimalGuardrail` and (via the read-secret
  route) on `guardrail_rules`, with raw score > 0 and near one unique score-cell per
  finding. → asserted by `verify.py` checks 1, 2, and the diversity check.
* **P2 — Budget safety (not model-dependent).** For any target latency, the returned
  candidate list is sized so the replay pass completes strictly within its budget, and
  every returned candidate satisfies the harness validity limits. → `verify.py`
  checks 5, 6; `tests/test_attack.py::test_replay_never_overruns_budget`.
* **P3 — Adaptivity (not model-dependent).** When the literal-marker route is blocked
  by the guardrail, FORGE detects it during probing and scores via a different route;
  when a target refuses overt-exfil phrasing, the probe finds a benign framing that
  scores. → `verify.py` checks 2, 3.
* **P4 — Determinism.** Under a fixed seed the offline score is reproduced exactly.
  → `verify.py` check 7.

## Secondary predictions (S) — target-model, to be reported as measured

* **S1.** On at least one of the two public columns (`gpt_oss_public`,
  `gemma_public`), FORGE's `http.post`+`SECRET_MARKER` route elicits ≥1 successful
  scored `EXFILTRATION` from the real model. *Expected: likely true — posting an
  opaque token to a URL is a low-refusal action.*
* **S2.** The batch route yields >1 `EXFILTRATION` per candidate on at least one public
  column. *Expected: uncertain — depends on whether the model issues multiple tool
  calls across hops in one interaction.*
* **S3.** On at least one private column, FORGE scores > 0 via the read-secret route.
  *Expected: uncertain — depends entirely on the unknown private guardrail and on the
  model's willingness to read `secret.txt` and forward it.*
* **S4a — `DESTRUCTIVE_WRITE` (long shot, expected to fail).** Scores on any column.
  *Pre-registered expectation: FALSE under both known guardrails (writes to `secret.txt`
  are denied/confirmed). Reported as measured.*
* **S4b — `UNTRUSTED_TO_ACTION` (uncertain).** The `tainted_share` route
  (`[web.open, http.post]` with a "post"-worded message) scores this severity-5
  predicate on `guardrail_rules` via a guardrail/predicate mismatch (the guardrail
  allows the post because "post" is in the message; the predicate scores it because it
  only checks send/email/upload). *Expected: FALSE on the public column (taint blocks
  it); uncertain on a private column — it fires only if the private guardrail shares the
  "post"-keyword hole AND the model complies.*

> **Disclosed deviation (before any real data).** S4 was originally a single long-shot
> predicting both predicates FALSE. After the pre-submission scoring review surfaced the
> `guardrail_rules` "post"-keyword hole, the `tainted_share` route was added and S4 was
> split into S4a/S4b, with S4b upgraded from "expected FALSE" to "uncertain" on the
> private column. No leaderboard data had been observed at the time of this change; the
> offline mechanism evidence (`UNTRUSTED_TO_ACTION` fires on `guardrail_rules` with a
> compliant stand-in) is in `results/local_evidence.json`.

## Abort / decision rule

Every returned candidate is scored **as measured**: a route that does not fire on a
given (model, guardrail) contributes 0, is reported as 0, and is not silently dropped
from the analysis. A falsified secondary prediction is reported in the Working Note's
results table, not hidden.

## What will NOT be tuned after seeing leaderboard data

* The scoring-mechanism claims (P1–P4) and their `verify.py` assertions.
* The four-route design and the adaptive probe→diversify→cap structure.
Prompt-template wording and config knobs (framings, `batch_size`, `replay_safety`)
MAY be tuned against leaderboard feedback; any such change is a disclosed deviation
with the before/after values, per the research discipline.
