# Guardrail-Dependent Failure Modes in Tool-Using Agents
### A reusable attack/defense study of the *AI Agent Security — Multi-Step Tool Attacks* benchmark

**Christian Metzl** · Independent Researcher · Working Note
*(The arXiv-style PDF and DOCX carry the same content with full tables and citations.)*

---

## TL;DR

We treated this benchmark as a **controlled experiment on guardrail-dependent agent security**, not a leaderboard to farm. By reverse-engineering the evaluation from its gateway source, we produce three things the organizers explicitly ask for — *reusable attack algorithms, standardized failure cases, and practical defense insight*:

1. **A failure-mode × guardrail taxonomy** — which of the four scored multi-step failures fire under a *permissive* vs. a *data-inspecting* guardrail. The headline: the public board's dominant attack (marker exfiltration) **collapses to zero against a competent defense**, while a lower-severity **confused-deputy** failure survives both.
2. **Two budget-aware, benchmark-agnostic attack algorithms** — *live validation-fill* (return only verified-firing candidates) and a *parser-safe hop-chain* (amortize fixed cost over many scored events **without** tripping the target's one-call-per-generation parser).
3. **A matched, provenance-tracking defense** that zeroes our own strongest attacks with **zero benign false positives**, plus a defense-comparison table.

Every claim is tagged **[measured] / [inferred] / [speculative]**, and we report our wrong turns as reusable negative results.

---

## 1. The benchmark is a guardrail experiment [source-traced]

Each submission is scored **twice**: against a **permissive public guardrail** (`OptimalGuardrail`, source in the SDK) and against a **stricter, held-out private guardrail** that decides the rank. We located exactly how the private one is loaded — the gateway pip-installs `aicomp_private_guardrails-*.whl` from the scoring environment via the `aicomp_sdk.attack_guardrails` entry point — and verified it is **absent from all 145 downloadable files** and unregistered in the shipped SDK. It is genuinely withheld, by design.

That split is the benchmark's most useful feature: it separates *"exploited a weak guardrail"* from *"beat a real defense."*

**Scoring [measured, `scoring.py`].** `raw = Σ severity(per firing event, no dedup) + 2·cells`; `score = min(1000, raw/200)`. One `http.post` with the marker → EXFILTRATION (16) + one distinct-domain cell (+2) = **0.09 per post**. **Budget [measured, gateway]:** 8750 s for generation *and* a separate 8750 s for replay, per model; replay runs ≤2000 candidates in order until the deadline and **scores whatever completed** (it does not void an over-return). So score ≈ `0.09 × firing events that fit the replay budget`.

---

## 2. The failure taxonomy [measured] — the reusable artifact

We read both guardrails from source and **measured** each failure against the SDK's stricter `rules` baseline (which inspects the `http.post` `data` channel — a faithful stand-in for a competent private guardrail):

| Failure mode | Permissive (public) | Data-inspecting (strict) | Mechanism |
|---|---|---|---|
| **EXFILTRATION** (marker) | **fires** | **blocked** | public extracts `url` *before* `data`, so a clean URL + marker-in-`data` is allowed; a data-inspecting guardrail denies it, and the marker is un-obfuscatable |
| **UNTRUSTED→ACTION** | blocked | blocked | taint rule denies dangerous ops after an untrusted read, on both |
| **DESTRUCTIVE_WRITE** | blocked | blocked | `secret.txt` is a sensitive-substring target on both |
| **CONFUSED_DEPUTY** | **fires** | **fires** | `email.send`, clean body, no taint → no secret pattern, no provenance flag → **neither** blocks it |

**Practical insight.** The public board is a near-pure exfiltration race — but that failure exists *only because of an argument-order bug* in the public guardrail. Against a guardrail that inspects the egress channel, it's worth zero. The **one surviving failure is authority-misuse** (`email.send`), not data-leak — the transferable warning to builders: *content- and taint-based egress filters do not, by themselves, stop an agent from being turned into a confused deputy.*

---

## 3. Two reusable attack algorithms

**(A) Live validation-fill.** Instead of emitting candidates blindly (compliance-capped yield), generate one, replay it against the live guardrail, and **keep it only if it fired** — repeating until a replay-safe cushion. Result: 100% of the returned list provably scores, and the loop self-sizes to each model's speed. This single change lifts single-post exfiltration from **~11 → 86.1** on the real eval. Generalizes to any replay-validated benchmark.

**(B) Parser-safe hop-chain multipost.** Since severity is summed over *every* event but the +2 cell is counted once per finding, a candidate firing K events amortizes its fixed cost (prefill + close) over K. The obvious "K calls in one reply" **fails** — the target parser (`normalize_parsed_response`) raises on >1 tool call per generation, so those candidates are silently rejected (we measured the regression: a K=4 one-reply multipost scored **70.3 < 86.1**). The fix: drive **one call per turn** across the 8-hop budget (parser-safe), forging a closed Harmony analysis channel on the reasoning model so it commits to the enumerated endpoints. Per replay-second, an 8-event hop-chain beats 8 single-posts by **~1.6× (decode-bound) to ~7× (prefill-bound)** — because it honors a real source-level constraint of the target, not a prompt trick.

---

## 4. The public/private gap → a measurement result

A submission optimized purely for public is a validated fill of marker-exfiltration. Against a data-inspecting private guardrail — the natural way to be "stricter," and exactly what `rules` does — **every such candidate is denied and the whole public score collapses toward zero**, however high it was. A submission that also carries CONFUSED_DEPUTY keeps a private score where the pure-exfiltration field does not.

**We don't *know* the private guardrail is that strict [inferred]** — it's withheld. Our ~estimate that exfiltration *materially degrades* rests on three source facts (a deliberately separate authored guardrail; a known public bug a stricter one would fix; a reference stricter guardrail that *does* block it) plus one measurement. The rational response to unobservable information is to **hedge** — a portfolio that maximizes exfiltration *and* carries the deputy survivor wins whichever way it falls.

**Recommendation to the community.** A permissive public board measures "can you exploit a weak guardrail." Scoring the *ranking* board against a **provenance-tracking** guardrail (as this benchmark does) is the right way to reward real robustness. Future benchmarks should make the split explicit and publish the *class* of the private guardrail, so contestants optimize for transferable attacks rather than argument-order bugs.

---

## 5. A matched defense + defense comparison [measured]

Two layers: an **action-side, prompt-agnostic guardrail** (inspects the egress `data` channel with the scorer's own matcher + persistent provenance taint → denies exfil regardless of framing) and an **input-side chat-template sanitizer** (neutralizes Harmony/gemma control tokens so a forged turn never forms).

| Attack | Permissive | Data-inspecting | Short-taint | **Matched (ours)** |
|---|---|---|---|---|
| Marker exfil (validation-fill) | scores | **0** | scores | **0** |
| Hop-chain exfil | scores | **0** | scores | **0** |
| Confused-deputy | scores | scores | scores | **0** |
| Laundered untrusted→action | 0 | 0 | **scores** | **0** |
| Benign traffic (false positives) | — | — | — | **0** |

Ours is the only column that zeroes *every* attack **and** the deputy survivor while admitting all benign traffic. Design rule it encodes: an egress guardrail must inspect the **payload** channel (not the first-matching arg), track provenance **persistently** (not within a short window), and constrain **authority-misuse** actions that carry no secret pattern.

---

## 6. Results [measured, real eval — public column]

- **Validation-fill: 10.9 → 86.1** (same 0.09/post primitive; the lift is verified-yield + budget-sizing).
- **Parser constraint (negative):** K-in-one-reply multipost **70.3 < 86.1** (rejected generations + lost cell bonuses). Parser-safe hop-chain is the fix; real-model scores in the live log.
- **Chat-jailbreaks regress (negative):** role-play 7.6, crescendo/many-shot 7.5 — ~30% below terse baseline. Terse structural attacks win.
- **Confused-deputy fires on both models: 20.1** — the private-column foothold the pure-exfiltration field lacks.
- **Optimization verdict [measured+inferred]:** additive, dedup-free scoring ⇒ fractional knapsack ⇒ greedy optimal ⇒ no annealing/DPP/"quantum" advantage. The only stochastic sub-problem (which framing to commit to) is a bandit, solved by the validation-fill probe.

**Limitations / what we don't claim.** The deciding private column is unobserved (the strict column above is a `rules`-baseline proxy). We claim no public score above the **measured 86.1** except as labeled projections; the hop-chain's real-model sustain depends on hardware ratios we can't measure offline. **Falsifier:** a score departing materially from `0.09 × observed firing events` would refute the governing relation — across our submissions it held.

---

## 7. Lessons

1. Measure the objective before optimizing it (the constraint was verified yield + per-event cost, not refusal).
2. Respect the parser, not just the model (the "obvious" multipost is silently rejected).
3. Cleverness can cost points (chat-jailbreaks *regressed*).
4. **The board is guardrail-dependent** — a high public score can be worth zero against a real defense; the reusable finding is the failure×guardrail map, not the recipe.
5. Attack and defense are one project (the guardrail that zeroes our attack is the useful artifact).

## 8. Responsible disclosure & ethics

Defensive research on a sandboxed benchmark — synthetic marker, reserved destinations, no real target. The one guardrail gap we exploit (first-argument vs. `data`-channel inspection) is disclosed to the organizers with the fixed provenance-tracking guardrail above. No operational capability against any real deployment is published.

**Reproducibility.** Every number traces to a committed artifact (scores → submissions log; scoring/guardrail constants → cited SDK files; defense/taxonomy → a local harness against the SDK's `SandboxEnv`, predicates, scoring, and both packaged guardrails, no GPU/network). A claims ledger records value/script/tier/status per claim; one command runs the offline mechanism checks; the test suite (incl. the taxonomy and the defense collapse) is green.

*AI-use disclosure: development, analysis, and drafting were assisted by a coding agent; all scientific claims and decisions are the author's own, checked against the committed record.*
