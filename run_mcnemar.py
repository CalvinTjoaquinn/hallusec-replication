"""McNemar's test + bootstrap CI comparing HalluSec vs SAST tools."""
import os
import sys
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import pandas as pd
import numpy as np
from scipy.stats import chi2
from run_all_detection import run_semgrep, run_codeql_batch, run_snyk_batch

def mcnemar_test(y_true, pred_a, pred_b):
    """McNemar's test between two classifiers."""
    b = 0  # A correct, B wrong
    c = 0  # A wrong, B correct

    for yt, pa, pb in zip(y_true, pred_a, pred_b):
        a_correct = (pa == yt)
        b_correct = (pb == yt)
        if a_correct and not b_correct:
            b += 1
        elif not a_correct and b_correct:
            c += 1

    # McNemar's test with continuity correction
    if b + c == 0:
        return 1.0, b, c  # No difference

    chi2_stat = (abs(b - c) - 1) ** 2 / (b + c)
    p_value = 1 - chi2.cdf(chi2_stat, df=1)
    return p_value, b, c


def bootstrap_ci(y_true, y_pred, n_bootstrap=1000, seed=42):
    """Bootstrap 95% CI for precision, recall, F1."""
    rng = np.random.RandomState(seed)
    n = len(y_true)

    precisions = []
    recalls = []
    f1s = []

    for _ in range(n_bootstrap):
        indices = rng.choice(n, size=n, replace=True)
        yt = y_true[indices]
        yp = y_pred[indices]

        tp = ((yt == 1) & (yp == 1)).sum()
        fp = ((yt == 0) & (yp == 1)).sum()
        fn = ((yt == 1) & (yp == 0)).sum()

        p = tp / (tp + fp) if (tp + fp) > 0 else 0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

        precisions.append(p)
        recalls.append(r)
        f1s.append(f1)

    return {
        'precision': (np.percentile(precisions, 2.5), np.percentile(precisions, 97.5)),
        'recall': (np.percentile(recalls, 2.5), np.percentile(recalls, 97.5)),
        'f1': (np.percentile(f1s, 2.5), np.percentile(f1s, 97.5)),
    }


def main():
    csv_dir = os.path.join(os.path.dirname(BASE_DIR), "csv")
    gt = pd.read_csv(os.path.join(csv_dir, 'ground_truth_11models.csv'))
    print(f"Ground truth: {len(gt)} samples")
    print(f"Positive: {(gt['ground_truth'] == 1).sum()}, Negative: {(gt['ground_truth'] == 0).sum()}")

    # Run SAST on ground truth samples
    print("\nRunning SAST tools on ground truth samples...")

    # Semgrep (per-sample)
    print("  Running Semgrep...")
    semgrep_detected = []
    for i, row in gt.iterrows():
        code = str(row.get('code', ''))
        language = str(row.get('language', 'python'))
        result = run_semgrep(code, language)
        semgrep_detected.append(1 if result['issues'] > 0 else 0)
        if (i + 1) % 50 == 0:
            print(f"    {i+1}/{len(gt)}")
    gt['semgrep_detected'] = semgrep_detected
    print(f"  Semgrep: {sum(semgrep_detected)} detections")

    # CodeQL (batch per language)
    print("  Running CodeQL...")
    codeql_detected = [0] * len(gt)
    for lang in gt['language'].unique():
        lang_mask = gt['language'] == lang
        codes = [(i, str(row['code'])) for i, row in gt[lang_mask].iterrows()]
        if not codes:
            continue
        results = run_codeql_batch(codes, lang)
        for idx, result in results.items():
            codeql_detected[idx] = 1 if result['issues'] > 0 else 0
    gt['codeql_detected'] = codeql_detected
    print(f"  CodeQL: {sum(codeql_detected)} detections")

    # Snyk (batch per language)
    print("  Running Snyk...")
    snyk_detected = [0] * len(gt)
    for lang in gt['language'].unique():
        lang_mask = gt['language'] == lang
        codes = [(i, str(row['code'])) for i, row in gt[lang_mask].iterrows()]
        if not codes:
            continue
        results = run_snyk_batch(codes, lang)
        for idx, result in results.items():
            snyk_detected[idx] = 1 if result['issues'] > 0 else 0
    gt['snyk_detected'] = snyk_detected
    print(f"  Snyk: {sum(snyk_detected)} detections")

    # Save updated ground truth with SAST
    gt.to_csv(os.path.join(csv_dir, 'ground_truth_11models.csv'), index=False)

    # Compute confusion matrices
    y_true = gt['ground_truth'].values
    hallusec_pred = gt['hallusec_detected'].astype(int).values
    semgrep_pred = gt['semgrep_detected'].values
    codeql_pred = gt['codeql_detected'].values
    snyk_pred = gt['snyk_detected'].values

    print("\n" + "=" * 60)
    print("CONFUSION MATRICES")
    print("=" * 60)

    for name, pred in [("HalluSec", hallusec_pred), ("Semgrep", semgrep_pred),
                        ("CodeQL", codeql_pred), ("Snyk", snyk_pred)]:
        tp = ((y_true == 1) & (pred == 1)).sum()
        fp = ((y_true == 0) & (pred == 1)).sum()
        fn = ((y_true == 1) & (pred == 0)).sum()
        tn = ((y_true == 0) & (pred == 0)).sum()
        p = tp / (tp + fp) if (tp + fp) > 0 else 0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        print(f"\n{name}:")
        print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
        print(f"  Precision={p:.3f}  Recall={r:.3f}  F1={f1:.3f}")

    # McNemar's tests
    print("\n" + "=" * 60)
    print("McNEMAR'S TESTS (HalluSec vs baselines)")
    print("=" * 60)

    for name, pred in [("Semgrep", semgrep_pred), ("CodeQL", codeql_pred), ("Snyk", snyk_pred)]:
        p_value, b, c = mcnemar_test(y_true, hallusec_pred, pred)
        print(f"\nHalluSec vs {name}:")
        print(f"  b (HalluSec correct, {name} wrong) = {b}")
        print(f"  c (HalluSec wrong, {name} correct) = {c}")
        print(f"  p-value = {p_value:.2e}")
        print(f"  Significant (p < 0.05): {'Yes' if p_value < 0.05 else 'No'}")

    # Bootstrap CIs
    print("\n" + "=" * 60)
    print("BOOTSTRAP 95% CI (1000 iterations)")
    print("=" * 60)

    for name, pred in [("HalluSec", hallusec_pred), ("Semgrep", semgrep_pred),
                        ("CodeQL", codeql_pred), ("Snyk", snyk_pred)]:
        ci = bootstrap_ci(y_true, pred)
        print(f"\n{name}:")
        print(f"  Precision: [{ci['precision'][0]:.3f}, {ci['precision'][1]:.3f}]")
        print(f"  Recall:    [{ci['recall'][0]:.3f}, {ci['recall'][1]:.3f}]")
        print(f"  F1:        [{ci['f1'][0]:.3f}, {ci['f1'][1]:.3f}]")


if __name__ == "__main__":
    main()
