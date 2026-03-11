"""Run CodeQL and Snyk Code on experiment samples, batched per language."""

import pandas as pd
import subprocess
import tempfile
import json
import os
import shutil
import time

# Config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_csv_dir = os.path.join(os.path.dirname(BASE_DIR), "csv")
CSV_PATH = os.path.join(_csv_dir, "exp_v4_results_multi_tool.csv")
OUTPUT_PATH = os.path.join(_csv_dir, "exp_v4_results_real_tools.csv")
TEMP_BASE = tempfile.mkdtemp(prefix="hallusec_sast_")

EXT_MAP = {"python": ".py", "javascript": ".js", "java": ".java"}
CODEQL_SUITE_MAP = {
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
}

def score_to_severity(score):
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score > 0: return "Low"
    return "None"

# CodeQL
def run_codeql_language(codes_with_idx: list, language: str) -> dict:
    """Run CodeQL on all code files for a given language."""
    results = {}
    ext = EXT_MAP.get(language, ".py")
    suite = CODEQL_SUITE_MAP.get(language)

    if not suite:
        for idx, _ in codes_with_idx:
            results[idx] = {"issues": 0, "severity": "None", "score": 0.0}
        return results

    batch_dir = tempfile.mkdtemp(prefix=f"codeql_{language}_", dir=TEMP_BASE)
    db_dir = os.path.join(batch_dir, "codeql_db")
    sarif_path = os.path.join(batch_dir, "results.sarif")

    file_to_idx = {}
    for idx, code in codes_with_idx:
        filename = f"sample_{idx}{ext}"
        filepath = os.path.join(batch_dir, filename)
        with open(filepath, 'w') as f:
            f.write(code if isinstance(code, str) else "")
        file_to_idx[filename] = idx
        results[idx] = {"issues": 0, "severity": "None", "score": 0.0}

    try:
        print(f"    Creating CodeQL database for {language} ({len(codes_with_idx)} files)...")
        t0 = time.time()
        create_result = subprocess.run(
            ['codeql', 'database', 'create', db_dir,
             f'--language={language}',
             f'--source-root={batch_dir}',
             '--overwrite', '--quiet'],
            capture_output=True, text=True, timeout=600
        )
        print(f"    DB created in {time.time()-t0:.1f}s (exit={create_result.returncode})")

        if create_result.returncode != 0:
            print(f"    ERROR: {create_result.stderr[:300]}")
            return results

        print(f"    Running CodeQL analysis...")
        t0 = time.time()
        analyze_result = subprocess.run(
            ['codeql', 'database', 'analyze', db_dir,
             '--format=sarif-latest',
             f'--output={sarif_path}',
             suite, '--quiet'],
            capture_output=True, text=True, timeout=600
        )
        print(f"    Analysis done in {time.time()-t0:.1f}s (exit={analyze_result.returncode})")

        if analyze_result.returncode != 0:
            print(f"    ERROR: {analyze_result.stderr[:300]}")
            return results

        with open(sarif_path) as f:
            sarif = json.load(f)

        total_findings = 0
        for finding in sarif.get('runs', [{}])[0].get('results', []):
            locations = finding.get('locations', [])
            if locations:
                uri = locations[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                filename = os.path.basename(uri)
                if filename in file_to_idx:
                    idx = file_to_idx[filename]
                    results[idx]["issues"] += 1
                    total_findings += 1

                    level = finding.get('level', 'warning')
                    sev_score = {'error': 9.0, 'warning': 7.0, 'note': 4.0}.get(level, 4.0)
                    if sev_score > results[idx]["score"]:
                        results[idx]["score"] = sev_score
                        results[idx]["severity"] = score_to_severity(sev_score)

        files_with_findings = sum(1 for r in results.values() if r['issues'] > 0)
        print(f"    Found {total_findings} findings in {files_with_findings}/{len(codes_with_idx)} files")

    except subprocess.TimeoutExpired:
        print(f"    TIMEOUT for {language}")
    except Exception as e:
        print(f"    ERROR: {e}")
    finally:
        try: shutil.rmtree(batch_dir)
        except: pass

    return results

# Snyk
def run_snyk_language(codes_with_idx: list, language: str) -> dict:
    """Run Snyk Code on all code files for a given language."""
    results = {}
    ext = EXT_MAP.get(language, ".py")

    batch_dir = tempfile.mkdtemp(prefix=f"snyk_{language}_", dir=TEMP_BASE)

    file_to_idx = {}
    for idx, code in codes_with_idx:
        filename = f"sample_{idx}{ext}"
        filepath = os.path.join(batch_dir, filename)
        with open(filepath, 'w') as f:
            f.write(code if isinstance(code, str) else "")
        file_to_idx[filename] = idx
        results[idx] = {"issues": 0, "severity": "None", "score": 0.0}

    try:
        print(f"    Running Snyk Code for {language} ({len(codes_with_idx)} files)...")
        t0 = time.time()
        result = subprocess.run(
            ['snyk', 'code', 'test', batch_dir, '--json'],
            capture_output=True, text=True, timeout=300
        )
        print(f"    Snyk done in {time.time()-t0:.1f}s (exit={result.returncode})")

        output = result.stdout
        if output:
            data = json.loads(output)

            findings = []
            if 'runs' in data:
                for run in data.get('runs', []):
                    findings.extend(run.get('results', []))

            total_findings = len(findings)
            for finding in findings:
                locations = finding.get('locations', [])
                if locations:
                    uri = locations[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                    filename = os.path.basename(uri)
                    if filename in file_to_idx:
                        idx = file_to_idx[filename]
                        results[idx]["issues"] += 1

                        level = finding.get('level', 'warning')
                        sev_score = {'error': 9.0, 'warning': 7.0, 'note': 4.0}.get(level, 4.0)
                        if sev_score > results[idx]["score"]:
                            results[idx]["score"] = sev_score
                            results[idx]["severity"] = score_to_severity(sev_score)

            files_with_findings = sum(1 for r in results.values() if r['issues'] > 0)
            print(f"    Found {total_findings} findings in {files_with_findings}/{len(codes_with_idx)} files")

    except subprocess.TimeoutExpired:
        print(f"    TIMEOUT for {language}")
    except json.JSONDecodeError:
        print(f"    JSON parse error for {language}")
    except Exception as e:
        print(f"    ERROR: {e}")
    finally:
        try: shutil.rmtree(batch_dir)
        except: pass

    return results


# Main
def main():
    print("=" * 70)
    print("RUNNING REAL CodeQL + Snyk Code ON ALL SAMPLES")
    print("(Semgrep results kept from existing run)")
    print("=" * 70)

    df = pd.read_csv(CSV_PATH)
    print(f"Loaded {len(df)} samples")
    print(f"Languages: {df['language'].value_counts().to_dict()}")

    # Initialize new columns
    df['real_codeql_issues'] = 0
    df['real_codeql_severity'] = 'None'
    df['real_codeql_score'] = 0.0
    df['real_snyk_issues'] = 0
    df['real_snyk_severity'] = 'None'
    df['real_snyk_score'] = 0.0

    # Run CodeQL per language
    print("\n[1/2] Running CodeQL...")
    for language in ['python', 'javascript', 'java']:
        lang_mask = df['language'] == language
        lang_indices = df[lang_mask].index.tolist()
        codes_with_idx = [(idx, df.at[idx, 'code']) for idx in lang_indices]

        print(f"\n  {language.upper()} ({len(lang_indices)} samples)")
        batch_results = run_codeql_language(codes_with_idx, language)

        for idx, result in batch_results.items():
            df.at[idx, 'real_codeql_issues'] = result['issues']
            df.at[idx, 'real_codeql_severity'] = result['severity']
            df.at[idx, 'real_codeql_score'] = result['score']

    # Run Snyk Code per language
    print("\n[2/2] Running Snyk Code...")
    for language in ['python', 'javascript', 'java']:
        lang_mask = df['language'] == language
        lang_indices = df[lang_mask].index.tolist()
        codes_with_idx = [(idx, df.at[idx, 'code']) for idx in lang_indices]

        print(f"\n  {language.upper()} ({len(lang_indices)} samples)")
        batch_results = run_snyk_language(codes_with_idx, language)

        for idx, result in batch_results.items():
            df.at[idx, 'real_snyk_issues'] = result['issues']
            df.at[idx, 'real_snyk_severity'] = result['severity']
            df.at[idx, 'real_snyk_score'] = result['score']

    # Summary
    print("\n" + "=" * 70)
    print("RESULTS COMPARISON: SIMULATED vs REAL")
    print("=" * 70)

    hallu_mask = df['has_hallucination'] == True
    n_hallu = hallu_mask.sum()
    total = len(df)

    print(f"\nTotal samples: {total}")
    print(f"Samples with hallucinations: {n_hallu}")

    print(f"\n{'Tool':<25} {'Any Det.':<12} {'Crit/High':<12} {'Hallu Det.':<12} {'Rate':<10}")
    print("-" * 70)

    for sev_col, tool_name in [
        ('semgrep_severity', 'Semgrep (real/existing)'),
        ('codeql_severity', 'CodeQL (SIMULATED)'),
        ('snyk_severity', 'Snyk (SIMULATED)'),
        ('real_codeql_severity', 'CodeQL (REAL)'),
        ('real_snyk_severity', 'Snyk (REAL)'),
    ]:
        if sev_col in df.columns:
            any_det = ((df[sev_col] != 'None') & df[sev_col].notna()).sum()
            crit_high = df[sev_col].isin(['Critical', 'High']).sum()
            hallu_crit = df.loc[hallu_mask, sev_col].isin(['Critical', 'High']).sum()
            rate = hallu_crit / n_hallu * 100 if n_hallu > 0 else 0
            print(f"  {tool_name:<23} {any_det:<12} {crit_high:<12} {hallu_crit:<12} {rate:.2f}%")

    # Save
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved to {OUTPUT_PATH}")

    # Cleanup
    try: shutil.rmtree(TEMP_BASE)
    except: pass

    print("\nDone!")

if __name__ == "__main__":
    main()
