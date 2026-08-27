"""Real-data dry-run — run this the moment the Kaggle competition data is available.

Everything upstream (notebook wiring, preset smokes, the public->private TRANSFER dry-run against
our MODELED persistent_provenance) is validated offline. The one thing that needs the Kaggle
download is the GROUND TRUTH: the real `aicomp_private_guardrails.persistent_provenance.Guardrail`
and the `kaggle_evaluation` JED gateway ship only in the competition dataset.

This script:
  1. Locates the competition data (glob common Kaggle mount points, or pass --data DIR).
  2. Imports the REAL private guardrail and registers it in harness/local_eval so the transfer
     dry-run can replay the public-generated list on the REAL private guardrail (not our model).
  3. Re-runs experiments/transfer_dryrun.py-style scoring on: optimal (public) + the REAL private
     guardrail, and prints whether our modeled permissive/strict bracketed reality.
  4. Points at the real gateway for the notebook dry-run (needs the model GGUFs too; see the
     forum "confirmation of exact model" thread for the CPU llama-cpp recipe).

Usage:
    python scripts/kaggle_dryrun.py                 # auto-locate the data
    python scripts/kaggle_dryrun.py --data /kaggle/input/ai-agent-security-...   # explicit
"""

from __future__ import annotations

import argparse
import glob
import importlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


def _find_private_guardrails(data_dir: str | None):
    roots = [data_dir] if data_dir else []
    roots += ["/kaggle/input", str(REPO), str(Path.home())]
    for r in roots:
        if not r:
            continue
        for hit in glob.glob(f"{r}/**/aicomp_private_guardrails", recursive=True):
            return str(Path(hit).parent)
        for hit in glob.glob(f"{r}/**/persistent_provenance*.py", recursive=True):
            # the module may ship flat; add its package root
            return str(Path(hit).resolve().parents[1])
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None, help="competition data dir (defaults to auto-locate)")
    args = ap.parse_args()

    root = _find_private_guardrails(args.data)
    if root is None:
        print("Real private guardrail NOT found. Download the competition data first "
              "(mcp__Kaggle__download_competition_data_files, or Kaggle 'Add Data'), then re-run.")
        print("Looked under: --data, /kaggle/input, repo, home. Nothing matched "
              "aicomp_private_guardrails / persistent_provenance.")
        return 2
    if root not in sys.path:
        sys.path.insert(0, root)
    print(f"Found private-guardrail package root: {root}")

    try:
        mod = importlib.import_module("aicomp_private_guardrails.persistent_provenance")
        RealGuard = getattr(mod, "Guardrail")
    except Exception as e:  # noqa: BLE001
        print(f"Import of aicomp_private_guardrails.persistent_provenance failed: {type(e).__name__}: {e}")
        print("Inspect the downloaded package layout and adjust the import.")
        return 3
    print("Imported REAL persistent_provenance.Guardrail. Source:")
    try:
        import inspect
        print(inspect.getsource(RealGuard)[:2000])
    except Exception:
        print("(source unavailable)")

    # Register it and run the transfer dry-run: generate on public, replay the SAME list on the
    # REAL private guardrail, compare against our modeled permissive/strict.
    from harness import local_eval as LE
    _orig = LE._guardrail_factory

    def factory(name):
        if name in ("persistent_provenance_REAL", "real_private"):
            return RealGuard
        return _orig(name)
    LE._guardrail_factory = factory

    import experiments.transfer_dryrun as T
    T.COLUMNS = ["optimal", "persistent_provenance_REAL",
                 "persistent_provenance", "persistent_provenance_strict"]
    print("\n--- TRANSFER DRY-RUN vs the REAL private guardrail (+ our models for comparison) ---")
    T.main()
    print("\nIf REAL != our permissive/strict models: update harness/guardrail_variants.py to match,")
    print("re-run the strategy check (sentinel vs real-secret coverage), and only then decide routing.")
    print("Next: notebook gateway dry-run needs the model GGUFs — use the forum CPU llama-cpp recipe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
