# Anticipated objections — FORGE

Every objection a competent, hostile reviewer could raise, stated in its **strongest**
form, each answered with committed evidence or an honest concession. Where the honest
answer is "the objection stands within scope X," we say so and constrain the claim.

---

**O1. "Your positive scores are from a mock, not the real models. This proves nothing
about the leaderboard."**
Partly conceded, and stated everywhere. The competition targets need a GPU and gated
weights we do not have in the build environment. The mock is a *compliant tool-following
stand-in*; it validates the SDK **scoring mechanism** — predicate firing for a given
trace shape, diversity counting, adaptivity, budget safety, candidate validity — none of
which depend on which model produced the trace. It does **not** measure real-model
compliance, and we claim no leaderboard number. Real-model outcomes are pre-registered as
predictions (`PREREGISTRATION.md`) to be reported as measured. The parts that are
model-independent (validity, no-overrun, formula-correctness, determinism) are the parts
that most often break a submission on the real evaluator, and those are verified.

**O2. "The whole thing rests on posting the literal string `SECRET_MARKER`. That's
gaming the sentinel, not a real attack."**
For the public guardrail, yes — and that is a finding about the *benchmark*, not a trick
we hide. The `EXFILTRATION` predicate honours the `SECRET_MARKER` sentinel by design
(`predicates.py`), the public guardrail inspects an `http.post`'s URL but not its data,
and posting an opaque token is a low-refusal action — so the sentinel route is the
correct, code-supported way to score the public column. We document it as a benchmark
weakness in `WORKING_NOTE.md` §6 and recommend scoring the data channel. Where a
guardrail closes the sentinel (the strict proxy), FORGE switches to the *genuine*
read-secret-then-forward exfiltration chain, which is a real attack.

**O3. "If the model refuses, you score nothing, so the algorithm is just prompt luck."**
Refusal is the real difficulty, and FORGE treats it as the search problem: it probes a
bank of framings per route and keeps the one that fires under the live guardrail
(`test_adapts_across_framings_for_stubborn_target`; `verify.py` 3). It cannot conjure
compliance from a model that refuses everything — and when none fires it degrades to a
small valid list with no crash (`verify.py` 9). We do not claim to defeat an arbitrarily
robust target; we claim to find a working framing when one exists in the bank.

**O4. "Returning up to 2000 candidates will make replay time out and zero your run."**
This is the failure we engineered against. FORGE sizes the returned list to
`replay_safety · budget` using a per-candidate cost model with an over-estimated hop
count, and only fills that budget. It holds across target latencies in the harness
(`verify.py` 6; `test_replay_never_overruns_budget`). Residual risk: if the *real*
per-hop replay latency materially exceeds what generation measured (e.g. much longer
contexts on replay), the estimate could be optimistic; `replay_safety = 0.5` plus the
hop over-estimate is the margin, and the knob is exposed for tuning.

**O5. "`guardrail_rules` is not the private guardrail; your strict-guardrail results are
meaningless."**
Conceded that it is not the private guardrail — we never claim it is, and the word
"proxy" is used wherever it appears. It is the SDK's own *stricter* baseline, the most
faithful public stand-in available, and it exercises the code path that matters (a
guardrail that blocks the sentinel but allows the read). Its role is to prove FORGE
*adapts* when a route is blocked, not to predict the private score. The adaptivity
mechanism (probe → detect blocked route → switch) is guardrail-agnostic.

**O6. "Batching several posts in one turn contradicts the system prompt 'call at most one
tool per turn' — models won't do it."**
The SDK allows multiple tool calls across the interaction's *hops* (one per hop), so a
multi-post trace is representable and the predicate stacks over it (validated directly:
a 4-post interaction yields 4 `EXFILTRATION`). Whether a given model issues several
across hops is uncertain (pre-registered S2). The design does not depend on it: a batch
candidate that yields one post degrades to a normal single-post finding, and the
raw-per-hop ranking demotes batching automatically if the probe shows it underperforms.

**O7. "You over-fit to the SDK you downloaded; the hidden evaluator may differ."**
The submission imports only `aicomp_sdk` contract types plus two pure-python helpers,
each behind a try/except fallback, and mirrors the documented limits as constants — so an
SDK move degrades gracefully rather than crashing. The behavioural facts we rely on are
in the *published* SDK the competition itself distributes; if the hidden evaluator
diverges, the adaptive probe (which measures the live guardrail rather than assuming it)
is the hedge.

**O8. "Diversity is fake — you just change the URL."**
True and intended: the *score-cell* keys on the `http.post` domain
(`cells.py:_bucket_url`), so distinct domains are distinct cells by the benchmark's own
definition. We flag this as a benchmark weakness (distinct destinations ≠ distinct
*mechanisms*) and recommend the fix in `WORKING_NOTE.md` §6. Within the current rules,
using it is correct, not deceptive.

**O9. "Where are the real citations / did you verify them?"**
The competition pages and the SDK are primary sources we read directly. The one external
paper (arXiv:2507.20526) is cited with only its verified leading authors and an explicit
"et al." for the unverified remainder, per the discipline of never inventing an author
name.

---

## Limitations (specific, enumerated)

1. **No real-model measurement.** All positive scores are offline against a stand-in;
   real GPT-OSS/Gemma compliance is unmeasured here (O1).
2. **Private guardrail unknown.** Strict-guardrail results use a proxy (O5).
3. **Compliance-bounded.** Against a sufficiently robust target the score is low; FORGE
   finds a working framing only if one exists in its bank (O3).
4. **Two predicates unreachable under known guardrails.** `DESTRUCTIVE_WRITE` and
   `UNTRUSTED_TO_ACTION` do not score under `OptimalGuardrail`/`guardrail_rules`; we
   report this as a negative rather than pretend otherwise.
5. **Budget estimate assumes representative probe latency.** A large generation↔replay
   latency gap could make the size estimate optimistic; mitigated by margins (O4).
6. **Offline harness runs are short** (60 s), 5 orders of magnitude below the real
   budget; they validate mechanism, not the real ceiling.
