"""
scanner.py
Runs Cppcheck + Flawfinder on the cloned target repo.
Returns unified list of findings with file, line, cwe, message, tool.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from pathlib import Path


# Flawfinder risk level 1-5, we care about 2 and above
FLAWFINDER_MIN_RISK = 2


def run_cppcheck(target_dir: str) -> list[dict]:
    print("[scanner] Running Cppcheck...")

    result = subprocess.run(
        [
            "cppcheck",
            "--enable=all",
            "--inconclusive",
            "--xml",
            "--xml-version=2",
            "--language=c++",
            "--suppress=missingIncludeSystem",
            "--suppress=missingInclude",
            target_dir,
        ],
        capture_output=True,
        text=True,
    )

    findings = []
    try:
        # cppcheck writes XML to stderr
        root = ET.fromstring(result.stderr)
        for error in root.findall(".//error"):
            severity = error.get("severity", "")
            if severity not in ("error", "warning"):
                continue

            location = error.find("location")
            if location is None:
                continue

            file_path = location.get("file", "")
            # only care about .cpp, .c, .h, .hpp files
            if not any(file_path.endswith(ext) for ext in [".cpp", ".c", ".h", ".hpp"]):
                continue

            cwe_id = error.get("cwe")
            cwe = f"CWE-{cwe_id}" if cwe_id else "UNKNOWN"

            findings.append({
                "tool": "cppcheck",
                "file": file_path,
                "line": int(location.get("line", 0)),
                "cwe": cwe,
                "message": error.get("msg", ""),
                "function_name": None,
            })

    except ET.ParseError as e:
        print(f"[scanner] Cppcheck XML parse error: {e}")

    print(f"[scanner] Cppcheck found {len(findings)} issues")
    return findings


def run_flawfinder(target_dir: str) -> list[dict]:
    print("[scanner] Running Flawfinder...")

    result = subprocess.run(
        [
            "flawfinder",
            "--csv",
            "--minlevel", str(FLAWFINDER_MIN_RISK),
            target_dir,
        ],
        capture_output=True,
        text=True,
    )

    findings = []
    lines = result.stdout.strip().splitlines()

    # flawfinder CSV format:
    # File,Line,Column,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context
    for line in lines:
        if not line or line.startswith("File"):
            continue
        parts = line.split(",")
        if len(parts) < 10:
            continue

        try:
            file_path = parts[0].strip().strip('"')
            line_num = int(parts[1].strip())
            cwe_field = parts[9].strip().strip('"')

            # cwe_field can be "CWE-119, CWE-120" — take the first one
            cwe = cwe_field.split(",")[0].strip() if cwe_field else "UNKNOWN"

            message = parts[6].strip().strip('"') if len(parts) > 6 else ""

            if not any(file_path.endswith(ext) for ext in [".cpp", ".c", ".h", ".hpp"]):
                continue

            findings.append({
                "tool": "flawfinder",
                "file": file_path,
                "line": line_num,
                "cwe": cwe,
                "message": message,
                "function_name": None,
            })
        except (ValueError, IndexError):
            continue

    print(f"[scanner] Flawfinder found {len(findings)} issues")
    return findings


def deduplicate(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for f in findings:
        key = (f["file"], f["line"], f["cwe"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan(target_dir: str) -> list[dict]:
    cppcheck_findings = run_cppcheck(target_dir)
    flawfinder_findings = run_flawfinder(target_dir)

    all_findings = cppcheck_findings + flawfinder_findings
    unique = deduplicate(all_findings)
    unique.sort(key=lambda x: (x["file"], x["line"]))

    print(f"[scanner] Total unique findings: {len(unique)}")
    return unique


if __name__ == "__main__":
    import sys
    results = scan(sys.argv[1])
    print(json.dumps(results, indent=2))
