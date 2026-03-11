"""Re-run HalluSec with the definition-check fix to reduce false positives."""
import os
import sys
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import pandas as pd
from run_all_detection import run_hallusec_on_df

base = os.path.join(os.path.dirname(BASE_DIR), "csv")

datasets = [
    ("new_models_internal.csv", "Internal (4 new models)"),
    ("internal_7models.csv", "Internal (7 old models)"),
    ("cyberseceval_new_models.csv", "CyberSecEval (4 new models)"),
    ("cyberseceval_generated.csv", "CyberSecEval (7 old models)"),
    ("securityeval_new_models.csv", "SecurityEval (4 new models)"),
    ("securityeval_results.csv", "SecurityEval (7 old models)"),
]

hallusec_cols = ['has_hallucination', 'hallucination_types', 'hallusec_severity',
                 'hallusec_score', 'n_hallucinations']

for filename, label in datasets:
    path = f"{base}/{filename}"
    print(f"\n{'='*60}")
    print(f"{label}: {filename}")
    print(f"{'='*60}")

    df = pd.read_csv(path)
    print(f"  Loaded {len(df)} samples")

    # Save old values for comparison
    old_hallu = df['has_hallucination'].sum() if 'has_hallucination' in df.columns else 0

    # Re-run HalluSec
    df = run_hallusec_on_df(df)

    new_hallu = df['has_hallucination'].sum()
    diff = new_hallu - old_hallu

    print(f"  Before fix: {old_hallu} hallucinations")
    print(f"  After fix:  {new_hallu} hallucinations")
    print(f"  Difference: {diff:+d} ({'fewer FP' if diff < 0 else 'same' if diff == 0 else 'more'})")

    df.to_csv(path, index=False)
    print(f"  Saved to {path}")

# Summary
print(f"\n{'='*60}")
print("FINAL SUMMARY")
print(f"{'='*60}")
for filename, label in datasets:
    df = pd.read_csv(f"{base}/{filename}")
    n = len(df)
    h = df['has_hallucination'].sum()
    print(f"  {label:<35} {h:>4}/{n:>5} ({h/n*100:.1f}%)")
