# Preprint — build & submission notes

`main.tex` is a self-contained LaTeX source (single file, embedded bibliography — no
BibTeX step needed). It compiles cleanly to an 8-page `main.pdf` with `pdflatex` (built
here; see the portability note below), and also builds on Overleaf/arXiv.


## Built outputs (in this directory)

- `main.pdf` — 8-page compiled PDF (built here with pdflatex).
- `main.docx` — Word version (built by `build_docx.py` from `main.md`).
- `main.md` — readable Markdown rendering.
- `main.tex` — the LaTeX source of record.

Rebuild: `make` (PDF) · `python build_docx.py` (DOCX).

**Portability note.** To compile in a minimal TeX environment, `main.tex` uses base
packages only — `url` instead of `hyperref` (so URLs render as plain text, not
clickable links) and plain `\hline` tables instead of `booktabs`. On arXiv/Overleaf you
may re-enable `hyperref` + `booktabs` for clickable links and finer table rules; the
content is identical.

## Build

```bash
make            # runs pdflatex twice (resolves refs); produces main.pdf
# or directly:
pdflatex main.tex && pdflatex main.tex
# or: upload main.tex to Overleaf, or to arXiv (it builds server-side).
```

## Before posting — fill these placeholders (they are marked \placeholder{...} in red)

1. **Affiliation** and **contact email** on the title page.
2. **§7.2 Real-model results** — the core empirical table: the four normalized
   leaderboard scores (`gpt_oss_public`, `gpt_oss_private`, `gemma_public`,
   `gemma_private`), the per-route firing rates actually observed on GPT-OSS-20B /
   Gemma-4, and an honest refusal accounting. Report each pre-registered prediction
   (`docs/PREREGISTRATION.md`) as pass/fail **as measured**, including any falsified.
3. **§9 Disclosure date / acknowledgement** for the two guardrail mismatches.

Until (2) is filled, the paper is an incentive-analysis + method + defense contribution
that stands on its own; the real-model claims are explicitly pre-registered predictions,
not results.

## Compliance & timing (see the repo-root answer for the rule citations)

- **Post after the Competition Period ends.** During the competition, the rules restrict
  public sharing of competition code to Kaggle's own forums; after it ends those
  restrictions lapse.
- **Do not redistribute competition data.** Cite the public MIT `aicomp_sdk` (already on
  PyPI); do not attach fixtures/dataset dumps or anything about the private guardrail
  (which we do not have).
- **License:** MIT (matches the winner-license requirement and the repo).
- **Responsible disclosure:** notify the organizers (OpenAI / Google / IEEE) about the
  two guardrail mismatches before posting; record the date in §9.
- **Originality & AI-use disclosure:** the paper is original work; the AI-assistance
  disclosure paragraph is included per the venue-neutral good practice.

## Provenance

The paper's substantive content mirrors, in academic form:
`docs/WORKING_NOTE.md`, `docs/BENCHMARK_MECHANICS.md`, `docs/PREREGISTRATION.md`,
`docs/CLAIMS_LEDGER.md`, `defense/`, and the committed evidence in `results/`. Numbers in
the tables trace to `results/local_evidence.json`, `results/defense_evidence.json`, and
`results/dpp_ablation.json`.
