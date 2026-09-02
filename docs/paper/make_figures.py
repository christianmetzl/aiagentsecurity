#!/usr/bin/env python3
"""Regenerate the working-note figures from MEASURED real-eval data.

Two figures, colorblind-safe (blue #2b6cb0 / orange #dd6b20 / gray #718096):
  fig_method.png   -- method progression: the validation-fill lift + the documented negatives.
  fig_defense.png  -- defense comparison matrix: which guardrail design stops which attack.

All bar values are MEASURED public scores from the real competition eval (see
results/real_submissions_log.md). No projected/inferred values appear in the figures.
"""
from __future__ import annotations
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import numpy as np
import os

BLUE, ORANGE, GRAY = "#2b6cb0", "#dd6b20", "#718096"
HERE = os.path.dirname(os.path.abspath(__file__))
plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})

# ---- Figure 1: method progression (MEASURED public scores) ------------------------------
# (label, score, kind)  kind: 'win' = the algorithm, 'neg' = documented negative, 'base' = prior axis
rows = [
    ("Crescendo + many-shot", 7.47, "neg"),
    ("Chat-jailbreak (role-play)", 7.58, "neg"),
    ("Blind single-post", 10.94, "base"),
    ("Batch-8 throughput", 14.92, "base"),
    ("2-msg packing", 17.75, "base"),
    ("Confused-deputy (email.send)", 20.10, "base"),
    ("Multipost-in-one-reply", 70.34, "neg"),
    ("Validation-fill single-post", 86.09, "win"),
]
rows.sort(key=lambda r: r[1])
labels = [r[0] for r in rows]
vals = [r[1] for r in rows]
colors = {"win": BLUE, "neg": ORANGE, "base": GRAY}
bar_colors = [colors[r[2]] for r in rows]

fig, ax = plt.subplots(figsize=(7.4, 3.5))
y = np.arange(len(rows))
ax.barh(y, vals, color=bar_colors, height=0.62)
ax.set_yticks(y); ax.set_yticklabels(labels)
for i, v in enumerate(vals):
    ax.text(v + 1.2, i, f"{v:.1f}", va="center", fontsize=9)
ax.set_xlabel("Public normalized score (measured, real eval)")
ax.set_xlim(0, 100)
ax.set_title("Method progression: the validation-fill lift, and what did NOT help", fontsize=11)
# annotations
ax.annotate("live validation-fill\n(verified yield + budget-sizing): 4.9x",
            xy=(86, 7), xytext=(34, 5.15),
            fontsize=8.5, color=BLUE, ha="left",
            arrowprops=dict(arrowstyle="->", color=BLUE))
ax.annotate("parser rejects K-calls-in-one-reply\n-> below single-post",
            xy=(70.34, 6), xytext=(20, 3.9), fontsize=8.5, color=ORANGE, ha="left",
            arrowprops=dict(arrowstyle="->", color=ORANGE))
ax.legend(handles=[Patch(color=BLUE, label="the algorithm (validation-fill)"),
                   Patch(color=GRAY, label="prior throughput axis"),
                   Patch(color=ORANGE, label="documented negative result")],
          loc="lower right", fontsize=8, frameon=False)
fig.tight_layout()
fig.savefig(os.path.join(HERE, "fig_method.png"), dpi=200, bbox_inches="tight")
plt.close(fig)

# ---- Figure 2: defense comparison matrix (MEASURED, local harness) ----------------------
# rows = attacks, cols = guardrail designs. cell 1 = attack SCORES (defense fails, red),
# cell 0 = blocked (defense works, green).
attacks = ["Marker exfil\n(validation-fill)", "Hop-chain exfil\n(multipost)",
           "Confused-deputy\n(email.send)", "Laundered\nuntrusted->action"]
guards = ["Permissive\n(public)", "Data-\ninspecting", "Short-\ntaint", "Matched\n(ours)"]
#              Perm  Data  ShortTaint  Matched
M = np.array([[1,    0,    1,          0],   # marker exfil
              [1,    0,    1,          0],   # hop-chain exfil
              [1,    1,    1,          0],   # confused-deputy
              [0,    0,    1,          0]])  # laundered untrusted->action

fig, ax = plt.subplots(figsize=(6.2, 3.4))
GREEN = "#2f855a"
cmap = matplotlib.colors.ListedColormap([GREEN, "#c53030"])  # 0->green(blocked), 1->red(scores)
ax.imshow(M, cmap=cmap, vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(len(guards))); ax.set_xticklabels(guards, fontsize=8.5)
ax.set_yticks(range(len(attacks))); ax.set_yticklabels(attacks, fontsize=8.5)
for i in range(M.shape[0]):
    for j in range(M.shape[1]):
        ax.text(j, i, "scores" if M[i, j] else "blocked",
                ha="center", va="center", color="white", fontsize=8, fontweight="bold")
ax.set_title("Defense comparison: which guardrail stops which attack", fontsize=11)
# highlight the matched column (the only all-blocked design; 0 benign false positives -- see caption)
ax.add_patch(plt.Rectangle((3-0.5, -0.5), 1, len(attacks), fill=False, edgecolor=BLUE, lw=2.5))
fig.tight_layout()
fig.savefig(os.path.join(HERE, "fig_defense.png"), dpi=200, bbox_inches="tight")
plt.close(fig)

# ---- Figure 3: the measured private-board collapse + rank inversion ---------------------
# MEASURED from the final leaderboard: our two finals' public vs private scores, and the
# resulting private-rank climb (public 1455 -> private 133, silver) as the exfil field collapses.
fig, (axL, axR) = plt.subplots(1, 2, figsize=(7.8, 3.2), gridspec_kw={"width_ratios": [1.15, 1]})

legs = ["public_max\n(exfil)", "deputy_max\n(deputy)"]
pub = [86.085, 20.095]
prv = [0.0, 20.095]  # exfil leg collapses below 20 (blocked); deputy survives unchanged
x = np.arange(2); w = 0.38
axL.bar(x - w / 2, pub, w, color=GRAY, label="public score")
axL.bar(x + w / 2, prv, w, color=[ORANGE, BLUE], label="private score")
axL.set_xticks(x); axL.set_xticklabels(legs, fontsize=9)
axL.set_ylabel("normalized score"); axL.set_ylim(0, 96)
axL.set_title("Our two finals: public → private", fontsize=10.5)
for i, (p, q) in enumerate(zip(pub, prv)):
    axL.text(i - w / 2, p + 1.5, f"{p:.1f}", ha="center", fontsize=8.5)
    if q == 0:
        axL.text(i + w / 2, 2.0, "→ 0\ncollapses", ha="center", va="bottom",
                 fontsize=8, color=ORANGE, fontweight="bold")
    else:
        axL.text(i + w / 2, q + 1.5, f"{q:.1f}\nsurvives", ha="center",
                 fontsize=8, color=BLUE, fontweight="bold")
axL.legend(fontsize=8, frameon=False, loc="upper center")

axR.plot([0, 1], [1455, 133], "-o", color=BLUE, lw=2.2, markersize=7)
axR.invert_yaxis()
axR.set_xlim(-0.35, 1.35); axR.set_xticks([0, 1])
axR.set_xticklabels(["public\nrank", "private\nrank"], fontsize=9)
axR.set_ylabel("leaderboard rank (of 4,251)")
axR.set_title("+1,284 places as the field collapses", fontsize=10.5)
axR.annotate("1,455", (0, 1455), textcoords="offset points", xytext=(8, 8), fontsize=9)
axR.annotate("133 · silver", (1, 133), textcoords="offset points", xytext=(-8, -6),
             fontsize=9, ha="right", color=BLUE, fontweight="bold")

fig.suptitle("The predicted collapse, measured on the private board", fontsize=11.5, y=1.03)
fig.tight_layout()
fig.savefig(os.path.join(HERE, "fig_collapse.png"), dpi=200, bbox_inches="tight")
plt.close(fig)

print("wrote fig_method.png, fig_defense.png and fig_collapse.png")
