"""Create ground truth labels for 11 models using regex-based verification."""
import os
import sys
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
import re
import pandas as pd
import numpy as np

# Same fake security function list as detector (for independent verification)
FAKE_SECURITY_FUNCTIONS = [
    "sanitize_sql", "sanitize_input", "sanitize_html", "sanitize_query",
    "sanitize_string", "sanitize_url", "sanitize_path", "sanitize_filename",
    "sanitize_email", "sanitize_data", "sanitize_output", "sanitize_request",
    "sanitize_response", "sanitize_header", "sanitize_cookie", "sanitize_param",
    "sanitize_user_input", "sanitize_form_data", "sanitize_json",
    "escape_html", "escape_sql", "escape_string", "escape_input",
    "escape_query", "escape_xml", "escape_js", "escape_shell",
    "escape_url", "escape_ldap", "escape_xpath", "escape_regex",
    "validate_token", "validate_auth", "validate_session",
    "validate_csrf", "validate_jwt", "validate_api_key",
    "validate_credentials", "validate_permission", "validate_access",
    "validate_signature", "validate_certificate", "validate_origin",
    "secure_hash", "secure_encrypt", "secure_decrypt", "secure_random",
    "secure_compare", "secure_token", "secure_password", "secure_key",
    "secure_sign", "secure_verify", "secure_encode", "secure_decode",
    "check_permission", "check_auth", "check_access", "check_role",
    "check_csrf", "check_token", "check_session", "check_signature",
    "check_certificate", "check_integrity", "check_origin",
    "filter_xss", "filter_sqli", "filter_input", "filter_html",
    "filter_script", "filter_malicious", "filter_dangerous",
    "prevent_injection", "prevent_xss", "prevent_csrf",
    "prevent_sqli", "prevent_overflow", "prevent_traversal",
    "clean_input", "clean_html", "clean_sql", "clean_data",
    "clean_string", "clean_output", "clean_request",
    "purify_html", "purify_input", "purify_data",
    "strip_tags_secure", "strip_dangerous", "strip_scripts",
    "encode_secure", "encode_safe", "decode_secure",
]

KNOWN_FAKE_PACKAGES = {
    "securepy", "pysanitize", "sqlsanitize", "xssfilter",
    "securecrypto", "authguard", "tokenvalidator", "inputcleaner"
}


def is_function_defined(func_name: str, code: str) -> bool:
    """Check if a function is defined (implemented) in the code."""
    definition_patterns = [
        rf'def\s+{func_name}\s*\(',
        rf'function\s+{func_name}\s*\(',
        rf'(?:const|let|var)\s+{func_name}\s*=\s*(?:function|\()',
        rf'{func_name}\s*=\s*(?:function|\([^)]*\)\s*=>)',
        rf'(?:public|private|protected|static)\s+\w+\s+{func_name}\s*\(',
        rf'(?:this|self)\.{func_name}\s*=\s*(?:function|\()',
    ]
    for pattern in definition_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            return True
    return False


def is_function_called(func_name: str, code: str) -> bool:
    """Check if a function is called in the code."""
    call_pattern = rf'\b{func_name}\s*\('
    return bool(re.search(call_pattern, code, re.IGNORECASE))


def has_fake_import(code: str, language: str) -> bool:
    """Check if code imports from known fake packages."""
    if language == "python":
        imports = re.findall(r'(?:from|import)\s+([\w.]+)', code)
        for imp in imports:
            base = imp.split('.')[0]
            if base.lower() in KNOWN_FAKE_PACKAGES:
                return True
    return False


def independent_check(code: str, language: str) -> dict:
    """Check if code calls fake security functions without defining them."""
    code = str(code) if code else ""

    hallucinated_funcs = []
    defined_funcs = []

    for func_name in FAKE_SECURITY_FUNCTIONS:
        if is_function_called(func_name, code):
            if is_function_defined(func_name, code):
                defined_funcs.append(func_name)
            else:
                hallucinated_funcs.append(func_name)

    has_fake_pkg = has_fake_import(code, language)

    is_hallucination = len(hallucinated_funcs) > 0 or has_fake_pkg

    h_type = []
    if hallucinated_funcs:
        h_type.append("H5")
    if has_fake_pkg:
        h_type.append("H1")

    return {
        "is_hallucination": is_hallucination,
        "hallucination_type": "+".join(h_type) if h_type else "none",
        "hallucinated_funcs": hallucinated_funcs,
        "defined_funcs": defined_funcs,
        "has_fake_import": has_fake_pkg,
    }


def create_stratified_sample(df, n_per_model=43, seed=42):
    """Create stratified sample: ~equal per model, balanced positive/negative."""
    np.random.seed(seed)

    # Run independent check on all samples
    results = []
    for i, row in df.iterrows():
        check = independent_check(row['code'], row['language'])
        results.append({
            'idx': i,
            'model': row['model'],
            'language': row['language'],
            'prompt_category': row.get('category', row.get('prompt_category', 'unknown')),
            'is_hallucination': check['is_hallucination'],
        })

    check_df = pd.DataFrame(results)

    sampled = []
    for model in df['model'].unique():
        model_df = check_df[check_df['model'] == model]
        pos = model_df[model_df['is_hallucination'] == True]
        neg = model_df[model_df['is_hallucination'] == False]

        # Try to get balanced sample
        n_pos = min(len(pos), n_per_model // 2 + 1)
        n_neg = min(len(neg), n_per_model - n_pos)
        # Adjust if not enough
        if n_pos + n_neg < n_per_model:
            if len(pos) > n_pos:
                n_pos = min(len(pos), n_per_model - n_neg)
            elif len(neg) > n_neg:
                n_neg = min(len(neg), n_per_model - n_pos)

        pos_sample = pos.sample(n=n_pos, random_state=seed) if n_pos > 0 else pd.DataFrame()
        neg_sample = neg.sample(n=n_neg, random_state=seed) if n_neg > 0 else pd.DataFrame()

        sampled.extend(pos_sample['idx'].tolist())
        sampled.extend(neg_sample['idx'].tolist())

        print(f"  {model}: {n_pos} pos + {n_neg} neg = {n_pos+n_neg} (available: {len(pos)} pos, {len(neg)} neg)")

    return sampled


def main():
    base = os.path.join(os.path.dirname(BASE_DIR), "csv")

    # Load both internal datasets
    df_old = pd.read_csv(f"{base}/internal_7models.csv")
    df_new = pd.read_csv(f"{base}/new_models_internal.csv")

    print(f"Old models: {len(df_old)} samples, models: {df_old['model'].unique()}")
    print(f"New models: {len(df_new)} samples, models: {df_new['model'].unique()}")

    # Combine
    combined = pd.concat([df_old, df_new], ignore_index=True)
    print(f"\nCombined: {len(combined)} samples, {combined['model'].nunique()} models")

    # Create stratified sample
    print("\nCreating stratified sample...")
    sample_indices = create_stratified_sample(combined, n_per_model=43, seed=42)
    gt_df = combined.iloc[sample_indices].copy()
    print(f"\nTotal ground truth samples: {len(gt_df)}")

    # Run independent check on each sample
    from run_all_detection import HallucinationDetectorV4
    detector = HallucinationDetectorV4()

    gt_rows = []
    for i, (_, row) in enumerate(gt_df.iterrows()):
        code = str(row.get('code', ''))
        language = str(row.get('language', 'python'))

        # Independent check (ground truth)
        check = independent_check(code, language)

        # Detector result
        hallucinations = detector.detect(code, language)
        detector_detected = len(hallucinations) > 0
        detector_types = str([h.type.value for h in hallucinations]) if hallucinations else ''

        gt_rows.append({
            'sample_id': i,
            'model': row['model'],
            'language': language,
            'prompt_category': row.get('category', row.get('prompt_category', 'unknown')),
            'code': code,
            'hallusec_detected': detector_detected,
            'hallusec_types': detector_types,
            'ground_truth': 1 if check['is_hallucination'] else 0,
            'hallucination_type': check['hallucination_type'],
            'hallucinated_funcs': str(check['hallucinated_funcs']) if check['hallucinated_funcs'] else '',
            'defined_funcs': str(check['defined_funcs']) if check['defined_funcs'] else '',
            'confidence': 1.0,
            'notes': '',
        })

    gt_result = pd.DataFrame(gt_rows)

    # Confusion matrix
    tp = ((gt_result['ground_truth'] == 1) & (gt_result['hallusec_detected'] == True)).sum()
    fp = ((gt_result['ground_truth'] == 0) & (gt_result['hallusec_detected'] == True)).sum()
    fn = ((gt_result['ground_truth'] == 1) & (gt_result['hallusec_detected'] == False)).sum()
    tn = ((gt_result['ground_truth'] == 0) & (gt_result['hallusec_detected'] == False)).sum()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n{'='*50}")
    print(f"GROUND TRUTH RESULTS")
    print(f"{'='*50}")
    print(f"Total samples: {len(gt_result)}")
    print(f"Ground truth positive: {(gt_result['ground_truth'] == 1).sum()}")
    print(f"Ground truth negative: {(gt_result['ground_truth'] == 0).sum()}")
    print(f"\nConfusion Matrix:")
    print(f"  TP={tp}  FP={fp}")
    print(f"  FN={fn}  TN={tn}")
    print(f"\nPrecision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1-Score:  {f1:.3f}")

    # Per-model breakdown
    print(f"\nPer-model breakdown:")
    for model in sorted(gt_result['model'].unique()):
        m = gt_result[gt_result['model'] == model]
        m_tp = ((m['ground_truth'] == 1) & (m['hallusec_detected'] == True)).sum()
        m_fp = ((m['ground_truth'] == 0) & (m['hallusec_detected'] == True)).sum()
        m_fn = ((m['ground_truth'] == 1) & (m['hallusec_detected'] == False)).sum()
        m_tn = ((m['ground_truth'] == 0) & (m['hallusec_detected'] == False)).sum()
        print(f"  {model:<25} TP={m_tp:>2} FP={m_fp:>2} FN={m_fn:>2} TN={m_tn:>2}")

    # Save
    output_path = f"{base}/ground_truth_11models.csv"
    gt_result.to_csv(output_path, index=False)
    print(f"\nSaved to {output_path}")

    return gt_result


if __name__ == "__main__":
    main()
