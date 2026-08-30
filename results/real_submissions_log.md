# Real-model submission log (Kaggle live eval)

First genuine real-model (GPT-OSS-20B + Gemma-4, CPU llama-cpp) scores for FORGE. These are the
**public** leaderboard scores only; the **private** score (which decides the final rank) is hidden
until the competition closes (2026-09-01). All are on the normalized ~0–1000 scale.

MEASURED — real competition eval, not the offline compliant mock.

## Batch 1 (submitted 2026-08-29)

| notebook | build | private_fraction | public score | status |
|---|---|---|---|---|
| V2 `…1c952288a2` | robust | 0.05 | **10.935** | Succeeded |
| V1 `…17bfbcc57f` | robust | 0.30 | **7.690** | Succeeded |
| V7 `…dc0fcdf06c` | robust | 0.15 | (pending) | running |
| V3 `…f362cee303` | robust | 0.45 | (pending) | running |
| V6 `…19a27d257f` | robust | 0.60 | (pending) | running |
| V4 `…b02747ced5` | **balanced (dense)** | 0.30 | — | **Kaggle Error** |
| V5 `…1bb1479552` | **aggressive (dense)** | 0.30 | — | **Kaggle Error** |

### Reads
- **Compliance CONFIRMED:** both completed runs scored > 0 → the real models comply with FORGE's
  routes at a useful rate. (Biggest prior unknown, now resolved.)
- **private_fraction lever behaves as designed:** pf=0.05 → 10.9 (more sentinels) > pf=0.30 → 7.7
  (more prefix reserved for private routes that score ~0 on public). That drop IS the public↔private
  tradeoff, real.
- **Dense builds error on the real eval** (both `enable_dense=True` builds → Kaggle Error, ~2h;
  the three non-dense robust builds ran). Go-forward = robust only.
- **Public scale:** ~7–11 vs public-leaderboard top ~147. We are low on PUBLIC (we did not grind
  dense throughput and have few iterations). Our bet is the PRIVATE board (different, harder
  guardrail; "final standings may differ").

### Open (organizer-unanswered as of 2026-08-27, forum 712642)
- Whether the final score is the **average of the 2 private** rows or the **average of all 4** rows.
  Hedged at the config level via the pf sweep; final 2 selected by reasoning at close.
