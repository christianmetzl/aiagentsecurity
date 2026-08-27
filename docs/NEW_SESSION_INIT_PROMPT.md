# New-session initialization prompt

Paste the block below as your FIRST message in a fresh Claude Code session opened on
`christianmetzl/aiagentsecurity`, branch `claude/agent-security-multistep-attack`.
(If the Kaggle connector is attached to your account, the fresh session should pick it up.)

---

You are continuing the FORGE project — our submission to win the 2026 Kaggle / OpenAI·Google·IEEE
"AI Agent Security — Multi-Step Tool Attacks" competition ($50k, deadline 2026-09-01, ~5 days
out, 5 submissions/day, Kaggle-notebook submissions only). I'm Christian Metzl, independent
researcher, no affiliation. Hold the Metzl Research Discipline: measured-vs-inferred separation,
honesty, a claims ledger, one-command reproduction, and NEVER overclaim (we already retracted
"airtight" once). Post the preprint only after the competition ends; cite competition data, do
not re-host it; disclose the two guardrail bugs + the per-event scoring observation to organizers
before publishing.

FIRST, before anything else, read these in order and confirm you've absorbed them:
1. `docs/KNOWLEDGE_TRANSFER.md`  (the full brain-dump — start here)
2. `docs/COMPETITION_INTEL.md`   (forum intelligence + game-changing brainstorm)
3. `docs/WORKING_NOTE.md`, `docs/CLAIMS_LEDGER.md`, `docs/BENCHMARK_MECHANICS.md`
Then run `git log --oneline -8` and `python -m pytest tests/test_attack.py -q` to confirm state
(expect 25 passed; the tree is clean at commit c93a2fa or later).

Key already-validated result to NOT re-litigate: the offline public→private transfer dry-run
(`experiments/transfer_dryrun.py`) proves FORGE's public-generated list is **DUAL-COLUMN** —
identical score on the public guardrail and both `persistent_provenance` private hypotheses — so
the routing decision is **hold, do NOT rebalance toward a private-only (real-secret read+post)
route**. That would trade all-column candidates for one-column with no measured upside.

State in one line: FORGE (`attack.py`) is done and green — adaptive density-packing + genuine
guardrail-breaking insurance routes, budget-safe, with build presets via `FORGE_BUILD`
(balanced/robust/aggressive). Two hedge submission notebooks are prepped. The real eval is slow
CPU llama-cpp, scores only ~250 candidates, runs unreliable non-deterministic models, and its
PRIVATE guardrail is the leaked `aicomp_private_guardrails.persistent_provenance`.

THEN do this, in priority order:
1. Confirm the Kaggle MCP tools load (`mcp__Kaggle__*`). If they do:
   a. Download the competition data (LOCAL analysis only — do NOT commit/redistribute). Read
      `kaggle_evaluation/jed_attack_*` to get the GROUND-TRUTH gateway: real budget, the exact
      candidate-scoring cap, ordering, timeout. Reconcile against our forum-inferred "~250
      candidates / DEFAULT_BUDGET_S=900" and tune `attack.py` (`max_return`, density, ordering).
   b. **Run `python scripts/kaggle_dryrun.py`** — it auto-locates the downloaded data, imports the
      REAL `aicomp_private_guardrails.persistent_provenance.Guardrail`, replays FORGE's list on it,
      and reports whether our modeled permissive/strict bracketed reality. If REAL differs, update
      `harness/guardrail_variants.py` to match and only THEN reconsider routing.
   c. DRY-RUN both notebooks against the real gateway offline (the `launch.py` `else` branch
      pattern in COMPETITION_INTEL.md) to catch wiring bugs before spending submissions.
   d. Pull forum threads 712642 (Evaluator FAQ, updated 2026-08-27) and 736099 ("One hint on
      crafting attacks"); fold any rule change / actionable hint into attack.py + the intel doc.
   If the Kaggle tools do NOT load, you can still run the real check from a **Kaggle notebook**:
   attach the competition data and run `python scripts/kaggle_dryrun.py` there (no MCP needed).
2. Have me test-submit the `robust` notebook once to confirm the gateway scores; then run the
   2-build hedge (robust + aggressive) across the 5/day budget.
3. Keep everything committed + pushed to `claude/agent-security-multistep-attack`, tests green.

Do not re-derive context from scratch — the KT doc has it. Ask me before any irreversible or
outward-facing action (submitting, posting to the forum, publishing the preprint).

---

## If you'd rather I (this session) hand off differently
- The whole repo is already on GitHub (`christianmetzl/aiagentsecurity`,
  `claude/agent-security-multistep-attack`), so a fresh session can `git clone`/checkout and has
  everything. The ZIP is a self-contained offline snapshot of the same state plus these two docs.
