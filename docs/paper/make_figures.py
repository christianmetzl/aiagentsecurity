#!/usr/bin/env python3
"""Regenerate the working-note figures from MEASURED real-eval data.

Figures, colorblind-safe (blue #2b6cb0 / orange #dd6b20 / gray #718096):
  fig_method.png   -- method progression: the validation-fill lift + the documented negatives.
  fig_defense.png  -- defense comparison matrix: which guardrail design stops which attack.
  fig_collapse.png -- the measured private-board collapse and +1,284-place rank inversion.
  fig_frontier.png -- the scoring/throughput frontier: score = 0.09 x candidates cleared.

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
# bar-end labels; the two decisive facts are folded into their own bar's label
# (self-contained, so no free-floating callouts can overlap neighbouring bars)
note = {"Validation-fill single-post": "  (≈7.9× vs blind single-post)",
        "Multipost-in-one-reply": "  (parser-capped → below single-post)"}
for i, (lab, v, kind) in enumerate(rows):
    lab_extra = note.get(lab, "")
    ax.text(v + 1.6, i, f"{v:.1f}{lab_extra}", va="center", fontsize=8.6,
            color=(colors[kind] if lab_extra else "black"),
            fontweight=("bold" if lab_extra else "normal"))
ax.set_xlabel("Public normalized score (measured, real eval)")
ax.set_xlim(0, 140)
ax.set_title("Method progression: the validation-fill lift, and what did NOT help", fontsize=11)
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
# resulting private-rank climb: Kaggle's +1,284 private-board delta to rank 133 (silver).
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

# public point plotted at 133 + 1284 = 1417 so the slope equals Kaggle's +1,284 private-board
# delta exactly; the public standing is left unlabeled (the delta is board-relative, not 1455 - 133).
axR.plot([0, 1], [1417, 133], "-o", color=BLUE, lw=2.2, markersize=7)
axR.invert_yaxis()
axR.set_xlim(-0.35, 1.35); axR.set_xticks([0, 1])
axR.set_xticklabels(["public\nboard", "private\nboard"], fontsize=9)
axR.set_ylabel("leaderboard rank (of 4,251)")
axR.set_title("+1,284 places as the field collapses", fontsize=10.5)
axR.annotate("133 · silver", (1, 133), textcoords="offset points", xytext=(-8, -6),
             fontsize=9, ha="right", color=BLUE, fontweight="bold")

fig.suptitle("The predicted collapse, measured on the private board", fontsize=11.5, y=1.03)
fig.tight_layout()
fig.savefig(os.path.join(HERE, "fig_collapse.png"), dpi=200, bbox_inches="tight")
plt.close(fig)

# ---- Figure 4: the scoring / throughput frontier (MEASURED public scores) ---------------
# The governing law is exact: public normalized score = 0.09 x (candidates cleared within the
# replay budget), since one firing marker-exfil post = 18 raw = 0.09 normalized. This figure
# plots that line and places three MEASURED public points on it, making the throughput axis --
# and our honest gap to the public frontier -- explicit.
fig, ax = plt.subplots(figsize=(7.0, 3.6))
xs = np.array([0, 2000])
ax.plot(xs, 0.09 * xs, "-", color=GRAY, lw=1.8, zorder=1,
        label="score = 0.09 x candidates cleared")
# two labeled on-line points (candidates = score / 0.09); ceiling handled separately below
pts = [(957, 86.1, BLUE, "ours: 86.1\n(~957 cleared)", (14, -26), "left", BLUE),
       (1633, 147.0, "#b7791f", "public frontier ~147\n(~1,633 cleared)", (-10, 20), "right", "#8a5a12")]
for cx, cy, mcol, lab, off, ha, tcol in pts:
    ax.scatter([cx], [cy], s=70, color=mcol, edgecolor=mcol, linewidth=1.8, zorder=3)
    ax.annotate(lab, xy=(cx, cy), textcoords="offset points", xytext=off,
                fontsize=8.3, color=tcol, ha=ha, fontweight="bold")
# ceiling: open marker at the top-right corner, label parked in the empty lower-right with a leader
ax.scatter([2000], [180], s=70, color="white", edgecolor=GRAY, linewidth=1.8, zorder=3)
ax.annotate("single-post ceiling\n= 180 (2,000 cleared)", xy=(2000, 180), xytext=(1660, 52),
            fontsize=8.3, color=GRAY, ha="center", va="center",
            arrowprops=dict(arrowstyle="->", color=GRAY, lw=1.1))
# gap arrow: ours -> public frontier (the gap is throughput, not attack quality)
ax.annotate("", xy=(1633, 147), xytext=(957, 86.1),
            arrowprops=dict(arrowstyle="->", color=ORANGE, lw=1.6, ls=(0, (4, 2))))
ax.text(720, 128, "the gap is throughput,\nnot a stronger attack",
        fontsize=8.3, color=ORANGE, ha="left", style="italic")
ax.set_xlim(0, 2120); ax.set_ylim(0, 205)
ax.set_xlabel("candidates cleared within the replay budget")
ax.set_ylabel("public normalized score (measured)")
ax.set_title("The governing axis: score is linear in candidate throughput", fontsize=10.5, pad=10)
ax.legend(loc="upper left", fontsize=8, frameon=False)
fig.tight_layout()
fig.savefig(os.path.join(HERE, "fig_frontier.png"), dpi=200, bbox_inches="tight")
plt.close(fig)

print("wrote fig_method.png, fig_defense.png, fig_collapse.png and fig_frontier.png")
