# Real-model submission log (Kaggle live eval)

First genuine real-model (GPT-OSS-20B + Gemma-4, CPU llama-cpp) scores for FORGE. These are the
**public** leaderboard scores only; the **private** score (which decides the final rank) is hidden
until the competition closes (2026-09-01). All are on the normalized ~0–1000 scale.

MEASURED — real competition eval, not the offline compliant mock.

## Batch 1 (submitted 2026-08-29) — private_fraction sweep, robust build

Sorted by `private_fraction` to show the calibration curve directly. All rows are the SAME robust
build; only `FORGE_PRIVATE_FRACTION` varies.

| notebook | build | private_fraction | public score | status |
|---|---|---|---|---|
| V2 `…1c952288a2` | robust | 0.05 | **10.935** | Succeeded |
| V7 `…dc0fcdf06c` | robust | 0.15 | **8.855** | Succeeded |
| V1 `…17bfbcc57f` | robust | 0.30 | **7.690** | Succeeded |
| V3 `…f362cee303` | robust | 0.45 | **5.740** | Succeeded |
| V6 `…19a27d257f` | robust | 0.60 | **4.290** | Succeeded |
| V8 `…c8896d1807` | **throughput** (terse batch-8) | 0.05 | **14.915** ⭐ NEW BEST | Succeeded |
| V4 `…b02747ced5` | **balanced (dense)** | 0.30 | — | **Kaggle Error** |
| V5 `…1bb1479552` | **aggressive (dense)** | 0.30 | — | **Kaggle Error** |

### Reads
- **Compliance CONFIRMED:** every completed run scored > 0 → the real models comply with FORGE's
  routes at a useful rate. (Biggest prior unknown, resolved.)
- **private_fraction is a clean, monotone, ~linear public-cost lever** — COMPLETE MEASURED
  calibration curve (all 5 points, robust build): 0.05→10.935, 0.15→8.855, 0.30→7.690, 0.45→5.740,
  0.60→4.290. Least-squares fit: **public ≈ 11.5 − 12.1·pf** (slope ≈ −1.2 public per +0.10 pf,
  intercept ≈ 11.5 = the robust public ceiling at pf=0). Every unit of private_fraction trades
  public-scoring sentinels for private-targeted routes that score **~0 on the public guardrail
  (OptimalGuardrail)**. This is exactly the modeled public↔private tradeoff, now confirmed across
  the full sweep. It also proves the private routes are being **emitted and accepted as valid
  candidates** (they consume budget linearly) — whether they SCORE is a private-column question,
  hidden until close. There is nothing more to learn about the private column from public pf points;
  the sweep is done.
- **Dense builds error on the real eval** (both `enable_dense=True` builds → Kaggle Error, ~2h;
  every non-dense robust build ran). Go-forward = robust/throughput (non-dense) only.
- **THROUGHPUT WINS ON PUBLIC (V8 = 14.915 ⭐):** the terse batch-8 recipe beat the best single-post
  robust (pf0.05 = 10.935) by **+36%** at the SAME private_fraction. So on the real eval, PACKING
  more posts-per-candidate is a real lever, not just a mock artifact — and the non-dense batch-8
  redesign avoided the OOM/Kaggle-Error that killed the multi-message dense builds (V4/V5). This
  overturns the earlier "public is throughput-capped for us" read: we were single-post-capped, not
  throughput-capped. **Strategy update:** batch-8 is now the WINNING SUBSTRATE; the next configs
  layer the compliance levers (role-play, Crescendo, many-shot) ONTO it rather than onto the slower
  single-post base. Built: `throughput_rp` (batch-8 + role-play-in-batch), `max_compliance` (batch-8
  + all levers), `throughput_pf30` (winning substrate at private-covering pf).
- **Still below public top (~147):** 14.9 vs ~147 (~10×). The leaders are almost certainly packing
  far more per candidate (multi-message dense, which errors for us) and/or higher real compliance.
  The bet remains the PRIVATE board (different, harder guardrail where dense exfil is likely blocked
  for everyone), but the throughput win means we are less structurally capped on public than feared.

### Back-out calibration (from the aggregate public scores; API pull 2026-08-29)
Public → raw (×200000/1000) → severity-5 events (÷16):
- pf0.05: 10.935 → ~2,190 raw → ~135 scored high-severity events
- pf0.30:  7.690 → ~1,540 raw → ~95 events
Reads: (1) real compliance is real but LOW — ~2–3% of the fully-compliant mock (mock optimal
≈ 90k raw); the models execute only a small fraction of our attempts (matches "refuse / malformed
JSON" reports). (2) Reserving 25% more prefix for private routes (pf0.05→0.30) cost ~40 public
events (~30%) — the lever behaves exactly as modeled. (3) Public leaders ~147 → ~1,800 events
≈ 13× our throughput — almost certainly the dense packing they got working and we can't (dense
errors for us); on PUBLIC we are throughput-capped. On PRIVATE, dense exfil is likely blocked for
everyone, so that advantage should evaporate — the thesis, in numbers.
privateScore column is blank via the API too → private is genuinely hidden until close.

### Open (organizer-unanswered as of 2026-08-27, forum 712642)
- Whether the final score is the **average of the 2 private** rows or the **average of all 4** rows.
  Hedged at the config level via the pf sweep; final 2 selected by reasoning at close.
