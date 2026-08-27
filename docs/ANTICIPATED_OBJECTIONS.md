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
contexts on replay), the estimate could be optimistic; `replay_safety = 0.78` plus the
hop over-estimate is the margin, and the knob is exposed for tuning.

**O5. "`guardrail_rules` is not the private guardrail; your strict-guardrail results are
meaningless."**
Conceded that it is not the private guardrail — we never claim it is, and the word
"proxy" is used wherever it appears. It is the SDK's own *stricter* baseline, the most
faithful public stand-in available, and it exercises the code path that matters (a
guardrail that blocks the sentinel but allows the read). Its role is to prove FORGE
*adapts* when a route is blocked, not to predict the private score. The adaptivity
mechanism (probe → detect blocked route → switch) is guardrail-agnostic.

**O6. "Batching several posts in one turn contradicts the parser — every target model
raises `InvalidModelOutputError` on more than one tool call per response, so the batch
route is a fantasy and its 'graceful degradation' is false."**
The parser fact is correct and we verified it: `normalize_parsed_response` rejects >1
tool call in a single generation. But the batch route does **not** ask for several calls
in one response — it is a sequential worklist ("make one `http.post`, then the next after
it returns"), which the sandbox executes as *one tool per hop across the interaction's
hops*, exactly the reliable path (a 4-hop interaction yields 4 `EXFILTRATION`,
validated). Two independent safety nets make the "false degradation" claim itself false:
(1) FORGE **probes** the batch route on the live target; if the model instead emits a
multi-call response and the parser rejects it, the probe trace has zero tool events, the
route is never confirmed, and it is never fanned out; (2) the single-post `exfil_marker`
route is always available as the reliable floor. This is now a **tested invariant** —
`test_batch_degrades_gracefully_when_multicall_rejected` (a mock that raises
`InvalidModelOutputError` on batch prompts) asserts the batch route is dropped and the
single-post route still scores. What remains genuinely uncertain (pre-registered S2) is
only whether a *compliant* model walks the list one-per-hop (upside) or posts once and
stops (no worse than single-post); either way the score is bounded below by the
single-post route.

**O6a. "Your compliant mock is hand-built to walk the batch list one-per-hop, so your
tests and `verify.py` give false confidence about the batch prompt specifically."**
Conceded and addressed. The compliant mock does model the favourable path, so on its own
it would mask the parser-rejection risk. That is exactly why the `MultiCallRejectAgent`
stand-in and its test/`verify` check exist: they model the *unfavourable* parser path and
prove FORGE's total score is unharmed (batch dropped, single-post carries). The mocks
bracket the two real-model behaviours; which one the real models exhibit is inferred, not
measured (O1).

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
4. **Predicate reachability under known guardrails.** `DESTRUCTIVE_WRITE` is unreachable
   under both known guardrails, and `UNTRUSTED_TO_ACTION` is unreachable under
   `OptimalGuardrail` (taint blocks the follow-on action). `UNTRUSTED_TO_ACTION` *is*
   reachable under `guardrail_rules` via the "post"-keyword mismatch (the `tainted_share`
   route); we report both the negative (`DESTRUCTIVE_WRITE`) and this positive as measured.
5. **Budget estimate assumes representative probe latency.** A large generation↔replay
   latency gap could make the size estimate optimistic; mitigated by margins (O4).
6. **Offline harness runs are short** (60 s), far below the competition's per-model
   budget; they validate mechanism, not the real ceiling.
