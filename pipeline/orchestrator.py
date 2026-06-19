"""
orchestrator.py
Main pipeline controller. Connects all phases in order.
Run by GitHub Actions with --target and --repo-path args.
"""

import argparse
import json
import os
import requests
import sys
from pathlib import Path

# add pipeline dir to path
sys.path.insert(0, str(Path(__file__).parent))

from scanner import scan
from slicer import slice_function
from manifest_check import check_manifest, check_inline_tag
from compiler import compile_patch
from fuzzer import run_fuzzer
from signer import sign_patch, verify_signature
from pr_manager import create_patch_pr, label_manual_review


MAX_RETRIES = 3
QWEN_URL = os.environ.get("QWEN_URL", "")
REPO_PATH = os.environ.get("REPO_PATH", "")    # "owner/repo"


def call_qwen(source_code: str, cwe: str, error_feedback: str = None) -> str | None:
    """
    Call Qwen running on your M4 Mac via ngrok URL.
    Returns patch string or None if call fails.
    """
    if not QWEN_URL:
        print("[qwen] ERROR: QWEN_URL not set")
        return None

    payload = {
        "source_code": source_code,
        "cwe": cwe,
        "error": error_feedback,
    }

    try:
        resp = requests.post(
            f"{QWEN_URL}/generate-patch",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("patch")
    except requests.RequestException as e:
        print(f"[qwen] Request failed: {e}")
        return None


def process_finding(finding: dict, target_dir: str) -> dict:
    """
    Run the full pipeline on a single finding.
    Returns a result dict describing what happened.
    """
    file_path = finding["file"]
    line = finding["line"]
    cwe = finding["cwe"]

    print(f"\n{'='*60}")
    print(f"Processing: {cwe} in {Path(file_path).name} line {line}")
    print(f"{'='*60}")

    # ── Phase 2a: Slice the vulnerable function ──────────────────────────
    sliced = slice_function(file_path, line)
    if sliced is None:
        return {"status": "skipped", "reason": "Could not slice function", **finding}

    finding["function_name"] = sliced["function_name"]
    finding["source_code"] = sliced["source_code"]

    # ── Phase 2b: Check exceptions manifest ─────────────────────────────
    exempt = check_manifest(file_path, sliced["function_name"], target_dir)
    if exempt["exempt"]:
        label_manual_review(REPO_PATH, finding, f"Exempted: {exempt['reason']}")
        return {"status": "exempted", "reason": exempt["reason"], **finding}

    # ── Phase 2c: Retry loop (patch → compile → fuzz) ───────────────────
    error_feedback = None
    signature_info = None

    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n[orchestrator] Attempt {attempt}/{MAX_RETRIES}")

        # Call Qwen for patch
        patch = call_qwen(sliced["source_code"], cwe, error_feedback)
        if patch is None:
            return {"status": "failed", "reason": "Qwen call failed", **finding}

        # Compile
        compile_result = compile_patch(patch, cwe)
        if not compile_result["success"]:
            error_feedback = f"Compilation error: {compile_result['error']}"
            print(f"[orchestrator] Compile failed, retrying... ({error_feedback})")
            continue

        # Fuzz
        fuzz_result = run_fuzzer(sliced["function_name"], patch)
        if not fuzz_result["passed"]:
            error_feedback = f"Fuzzer crash: {fuzz_result['stack_trace']}"
            print(f"[orchestrator] Fuzz failed, retrying...")
            continue

        # ── Phase 3: Sign ────────────────────────────────────────────────
        signature_info = sign_patch(patch, sliced["function_name"])
        if not signature_info["signed"]:
            return {"status": "failed", "reason": "Signing failed", **finding}

        # ── Phase 5a: Inline tag check ───────────────────────────────────
        inline = check_inline_tag(patch, sliced["function_name"])
        if inline["exempt"]:
            label_manual_review(
                REPO_PATH, finding,
                f"Developer secops-ignore tag at line {inline['line']}: {inline['reason']}"
            )
            return {"status": "exempted", "reason": inline["reason"], **finding}

        # ── Phase 5b: Integrity check ────────────────────────────────────
        if not verify_signature(patch, signature_info):
            label_manual_review(REPO_PATH, finding, "Integrity violation — signature mismatch")
            return {"status": "integrity_violation", **finding}

        # ── Phase 5c: Create PR ──────────────────────────────────────────
        finding["source_code"] = sliced["source_code"]
        pr = create_patch_pr(REPO_PATH, finding, patch, signature_info)
        return {
            "status": "patched",
            "pr_url": pr["pr_url"],
            "attempts": attempt,
            **finding,
        }

    # All retries exhausted
    label_manual_review(REPO_PATH, finding, f"All {MAX_RETRIES} patch attempts failed")
    return {"status": "failed", "reason": "Max retries exhausted", **finding}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Path to cloned target repo")
    parser.add_argument("--repo-path", required=True, help="owner/repo of target")
    args = parser.parse_args()

    global REPO_PATH
    REPO_PATH = args.repo_path

    # ── Phase 2: Scan ────────────────────────────────────────────────────────
    findings = scan(args.target)

    if not findings:
        print("[orchestrator] No vulnerabilities found. Exiting.")
        sys.exit(0)

    print(f"[orchestrator] Processing {len(findings)} findings...")

    results = []
    for finding in findings:
        result = process_finding(finding, args.target)
        results.append(result)
        print(f"[orchestrator] {result['status'].upper()}: {finding.get('function_name', '?')} ({finding['cwe']})")

    # Write report
    report = {
        "total": len(results),
        "patched": len([r for r in results if r["status"] == "patched"]),
        "failed": len([r for r in results if r["status"] == "failed"]),
        "exempted": len([r for r in results if r["status"] == "exempted"]),
        "results": results,
    }

    with open("/tmp/secops_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[orchestrator] Done. {report['patched']} patched, "
          f"{report['failed']} failed, {report['exempted']} exempted.")


if __name__ == "__main__":
    main()
