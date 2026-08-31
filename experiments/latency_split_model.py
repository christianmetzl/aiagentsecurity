#!/usr/bin/env python3
"""Back out the (gemma, gpt-oss) per-model split of public_max = 86.085.

We cannot run the real GGUF targets here (no GPU / gated weights) and Kaggle exposes only the
aggregate public score, so the split is not directly observable. This is a CALIBRATED MODEL, not a
simulation of the models: it combines
  * the VERIFIED scoring (0.09 normalized per firing single-post candidate; aicomp_sdk/scoring.py),
  * the per-model replay budget B (~0.98 * 9000 s, from the ~13 h real-eval runtime = gen+replay per
    model x2), capped at 2000 candidates (MAX_REPLAY_FINDINGS), and
  * REPORTED real per-candidate latencies from the competitor code (nctuan JED split comment:
    gpt_oss ~20.4 s, gemma ~8.5 s at their module defaults; the Harmony forge suppresses gpt-oss CoT
    and lowers its latency toward gemma's),
against our two MEASURED anchors (public_max=86.085, ceiling_breaker=70.335).

row_score(L) = 0.09 * min(2000, B / L)      # L = per-candidate replay latency (s) for that model
public = mean(row_gpt, row_gemma)

The mean is one equation in two unknown latencies, so the split is a FAMILY of solutions. We print
that family and what each member implies for the retune -- and show which single experiment
(public_max_nosplit) collapses the family to a point.
"""
from __future__ import annotations

B = 0.98 * 9000.0        # per-model replay budget (s), measured-runtime-consistent
CAP = 2000               # MAX_REPLAY_FINDINGS
PER = 0.09               # normalized score per firing single-post candidate (verified)
PUBLIC_MAX = 86.085      # MEASURED
CEILING_BREAKER = 70.335 # MEASURED (multipost on the gemma row only)


def row(latency_s: float) -> float:
    """Row score for a per-candidate replay latency."""
    n = min(CAP, B / latency_s)
    return PER * n


def latency_for_row(target: float) -> float:
    """Invert row(): the per-candidate latency that yields a given row score."""
    n = target / PER
    n = min(CAP, n)
    return B / n


print(f"Budget B={B:.0f}s  cap={CAP}  per-candidate={PER}  ->  row ceiling = {PER*CAP:.1f}\n")
print(f"Anchors (MEASURED):  public_max mean = {PUBLIC_MAX}  ->  row_gpt + row_gemma = {2*PUBLIC_MAX:.2f}")
print(f"                     ceiling_breaker mean = {CEILING_BREAKER}  (gemma row = K=4 multipost)\n")

# Sweep the gemma row score; the gpt-oss row is forced by the 86.085 mean. Report the implied
# per-candidate latency of each row (and flag physically implausible members).
print("  gemma_row  gpt_row |  L_gemma   L_gpt  |  read")
print("  --------- -------- | -------- -------- | ----")
for r_g in (79.0, 86.0, 93.4, 100.0, 115.0, 130.0, 145.0):
    r_o = 2 * PUBLIC_MAX - r_g
    if r_o <= 0 or r_o > PER * CAP:
        continue
    Lg, Lo = latency_for_row(r_g), latency_for_row(r_o)
    if r_g > r_o:
        read = "gpt-oss the bottleneck; forge NOT helping much -> big headroom" if Lo > 1.4 * Lg \
               else "both rows close; forge already working -> little headroom"
    else:
        read = "gpt-oss faster than gemma (implausible for a reasoning model)"
    print(f"   {r_g:6.1f}   {r_o:6.1f} |  {Lg:6.2f}  {Lo:6.2f}  | {read}")

print("\nAnchor from the competitor's REPORTED latencies (gemma 8.5s, gpt-oss forged toward it):")
Lg_anchor = 8.5
rg = row(Lg_anchor)
ro = 2 * PUBLIC_MAX - rg
Lo_implied = latency_for_row(ro)
print(f"  If gemma is at 8.5 s -> gemma row {rg:.1f}; then gpt-oss row {ro:.1f} => gpt-oss ~{Lo_implied:.1f} s/candidate")
print(f"  (gpt-oss unforged ~20.4 s -> a forged {Lo_implied:.1f} s means the forge cut CoT ~{100*(1-Lo_implied/20.4):.0f}%)")

# What the retune levers do, at two representative splits. Best realistic forge case = bring the
# gpt-oss row to gemma's measured speed (~8.5 s); "halving" below that is unphysical for a
# reasoning model that still prefills + emits the tool call.
GEMMA_FLOOR_S = 8.5
print("\nRetune leverage (what each lever does to the 86.085 mean):")
for label, r_g, r_o in [("split A  (gemma 93 / gpt 79 : gpt already forged ~10s, near-ceiling)", 93.4, 78.8),
                        ("split B  (gemma 130 / gpt 42 : gpt ~19s, forge weak, room)", 130.0, 42.2)]:
    Lg, Lo = latency_for_row(r_g), latency_for_row(r_o)
    B2 = B * (0.99 / 0.98)                                   # frac 0.99 vs 0.98
    mean99 = (PER * min(CAP, B2 / Lg) + PER * min(CAP, B2 / Lo)) / 2
    r_o_best = PER * min(CAP, B / GEMMA_FLOOR_S)             # gpt-oss forged to gemma-speed
    mean_forge = (r_g + r_o_best) / 2
    print(f"  {label}")
    print(f"      frac 0.99                 -> mean {mean99:5.1f}  (+{mean99-PUBLIC_MAX:4.1f})")
    print(f"      gpt-oss forged to gemma-speed -> mean {mean_forge:5.1f}  (+{mean_forge-PUBLIC_MAX:4.1f})   [gpt row {r_o:.0f}->{r_o_best:.0f}]")

print("\nWhat public_max_nosplit will reveal (forge OFF -> gpt-oss reverts to ~20.4 s):")
Lg_A = latency_for_row(93.4); ro_off = PER * min(CAP, B / 20.4)
print(f"  If split A (forge working): nosplit ~= {(93.4 + ro_off)/2:.0f}  (a BIG drop from 86) "
      f"-> forge is worth ~{86 - (93.4 + ro_off)/2:.0f} pts; gpt-oss already near its floor, little more to gain.")
print(f"  If split B (forge weak):    nosplit ~= {(130.0 + ro_off)/2:.0f}  (~unchanged from 86) "
      f"-> the forge is NOT working; FIXING it is the big lever (+~25 -> ~112).")
