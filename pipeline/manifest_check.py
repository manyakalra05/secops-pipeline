"""
manifest_check.py
Two checks:
  1. .secops-exceptions.yaml  — checked in Phase 2, before LLM call
  2. // secops-ignore comments — checked in Phase 5, before merge
"""

import yaml
from pathlib import Path


MANIFEST_PATH = Path(__file__).parent.parent / ".secops-exceptions.yaml"


def _load_manifest() -> list[dict]:
    if not MANIFEST_PATH.exists():
        return []
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f) or {}
    return data.get("exceptions", [])


def check_manifest(file_path: str, function_name: str, repo_root: str) -> dict:
    """
    Phase 2: is this file/function in the exceptions manifest?
    Returns {"exempt": bool, "reason": str|None, "ticket": str|None}
    """
    exceptions = _load_manifest()
    if not exceptions:
        return {"exempt": False, "reason": None, "ticket": None}

    try:
        rel_path = str(Path(file_path).relative_to(repo_root))
    except ValueError:
        rel_path = file_path

    for entry in exceptions:
        entry_file = entry.get("file", "")
        if rel_path == entry_file or file_path.endswith(entry_file):
            entry_function = entry.get("function")
            if entry_function is None or entry_function == function_name:
                print(f"[manifest] EXEMPT: {rel_path}::{function_name} — {entry.get('reason')}")
                return {
                    "exempt": True,
                    "reason": entry.get("reason"),
                    "ticket": entry.get("ticket"),
                }

    return {"exempt": False, "reason": None, "ticket": None}


def check_inline_tag(source_code: str, function_name: str) -> dict:
    """
    Phase 5: does the patched function contain a // secops-ignore tag?
    Returns {"exempt": bool, "reason": str|None, "line": int|None}
    """
    TAG = "secops-ignore:"
    for i, line in enumerate(source_code.splitlines(), start=1):
        if TAG in line:
            reason = line[line.index(TAG) + len(TAG):].strip()
            print(f"[manifest] Inline tag in '{function_name}' at line {i}: {reason}")
            return {"exempt": True, "reason": reason, "line": i}

    return {"exempt": False, "reason": None, "line": None}
