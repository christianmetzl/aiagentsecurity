#!/usr/bin/env python3
"""Generate the working-note figures (colorblind-safe, academic style)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

BLUE, ORANGE, GRAY = "#2b6cb0", "#dd6b20", "#718096"
plt.rcParams.update({
    "font.size": 11, "font.family": "serif", "axes.spines.top": False,
    "axes.spines.right": False, "axes.grid": True, "grid.alpha": 0.25,
    "grid.linewidth": 0.6, "figure.dpi": 150,
})


def _clean(ax):
    ax.tick_params(length=3)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRAY)


# --- Fig 1: measured private-fraction sweep -------------------------------------
pf = np.array([0.05, 0.15, 0.30, 0.45, 0.60])
pub = np.array([10.935, 8.855, 7.690, 5.740, 4.290])
m, b = np.polyfit(pf, pub, 1)
r2 = 1 - np.sum((pub-(m*pf+b))**2)/np.sum((pub-pub.mean())**2)
fig, ax = plt.subplots(figsize=(5.2, 3.4))
xs = np.linspace(0.0, 0.65, 50)
ax.plot(xs, m * xs + b, color=GRAY, lw=1.4, ls="--",
        label=f"fit: public $\\approx$ {b:.1f} $-$ {abs(m):.1f}$\\cdot$pf  ($R^2$={r2:.2f})")
ax.plot(pf, pub, "o", color=BLUE, ms=7, label="measured (real eval)")
for x, y in zip(pf, pub):
    ax.annotate(f"{y:.2f}", (x, y), textcoords="offset points", xytext=(6, 6),
                fontsize=9, color=BLUE)
ax.set_xlabel("private_fraction reserved for public-null routes")
ax.set_ylabel("public score")
ax.set_title("Private-coverage lever is clean and linear", fontsize=11, loc="left")
ax.legend(frameon=False, fontsize=9, loc="upper right")
ax.set_xlim(0, 0.65); ax.set_ylim(0, 12)
_clean(ax); fig.tight_layout(); fig.savefig("fig_pf_sweep.png"); plt.close(fig)

# --- Fig 2: lever ladder (projection) -------------------------------------------
stages = ["LB60 floor\n(distinct-record ETL)", "+ token-min", "+ sustain-aware\nbandit probe",
          "+ bounded\nhybrid"]
vals = [58, 97, 158, 227]
fig, ax = plt.subplots(figsize=(5.6, 3.4))
bars = ax.bar(range(len(vals)), vals, color=BLUE, width=0.62, zorder=3)
bars[0].set_color(GRAY)
ax.axhline(147.53, color=ORANGE, lw=1.6, ls="--", zorder=2)
ax.annotate("public leader 147.53", (len(vals) - 0.5, 147.53), textcoords="offset points",
            xytext=(-4, 6), ha="right", fontsize=9, color=ORANGE)
for i, v in enumerate(vals):
    ax.annotate(f"{v}", (i, v), textcoords="offset points", xytext=(0, 4), ha="center",
                fontsize=10, color="#1a1a1a")
ax.set_xticks(range(len(stages))); ax.set_xticklabels(stages, fontsize=8.5)
ax.set_ylabel("projected public score")
ax.set_title("Lever ladder above the competitor floor  (inferred)", fontsize=10.5, loc="left")
ax.set_ylim(0, 245); _clean(ax); fig.tight_layout(); fig.savefig("fig_lever_ladder.png"); plt.close(fig)

# --- Fig 3: defense collapse (dumbbell) -----------------------------------------
builds = ["gpt_oss_max", "forgery", "max_compliance"]
attack = [6.75, 6.87, 23.78]
y = np.arange(len(builds))[::-1]
fig, ax = plt.subplots(figsize=(5.4, 2.9))
for yi, a in zip(y, attack):
    ax.plot([0, a], [yi, yi], color=GRAY, lw=1.3, zorder=1)
ax.plot(attack, y, "o", color=BLUE, ms=8, label="vs public guardrail", zorder=3)
ax.plot([0] * len(y), y, "o", color=ORANGE, ms=8, label="vs FORGE defense", zorder=3)
for yi, a in zip(y, attack):
    dx = (-26, 4) if a > 20 else (6, 4)
    ax.annotate(f"{a:.1f}", (a, yi), xytext=dx, textcoords="offset points", fontsize=9, color=BLUE)
    ax.annotate("0", (0, yi), xytext=(-12, 4), textcoords="offset points", fontsize=9, color=ORANGE)
ax.set_yticks(y); ax.set_yticklabels(builds, fontsize=9.5)
ax.set_xlabel("normalized attack score")
ax.set_title("Matched defense collapses every attack build to 0", fontsize=10.5, loc="left")
ax.legend(frameon=False, fontsize=9, loc="center right")
ax.set_xlim(-2, 29); _clean(ax); fig.tight_layout(); fig.savefig("fig_defense.png"); plt.close(fig)

print("wrote fig_pf_sweep.png, fig_lever_ladder.png, fig_defense.png")
