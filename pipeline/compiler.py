"""
compiler.py
Compiles the patched function inside Docker for isolation.
Falls back to local g++ if Docker is unavailable.
"""

import subprocess
import tempfile
import os


def _wrap_patch(patch_code: str) -> str:
    """Wrap the patch in a minimal compilable translation unit."""
    return f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

{patch_code}

int main() {{ return 0; }}
"""


def _write_temp(content: str, suffix: str) -> str:
    tmp = tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, mode="w", encoding="utf-8"
    )
    tmp.write(content)
    tmp.close()
    return tmp.name


def compile_patch(patch_code: str, cwe: str) -> dict:
    """
    Compile patched code. Returns:
    {"success": bool, "error": str|None, "binary_path": str|None}
    """
    src = _write_temp(_wrap_patch(patch_code), ".cpp")
    out = src.replace(".cpp", ".out")

    print(f"[compiler] Compiling patch for {cwe}...")

    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network=none",
                "--memory=512m",
                "--cpus=1",
                "-v", f"{src}:{src}:ro",
                "-v", f"{os.path.dirname(out)}:{os.path.dirname(out)}",
                "gcc:latest",
                "g++",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-g", "-O1",
                "-o", out,
                src,
            ],
            capture_output=True, text=True, timeout=60,
        )
        return _parse_compile_result(result, out)

    except FileNotFoundError:
        # Docker not available, compile locally
        print("[compiler] Docker unavailable, compiling locally...")
        result = subprocess.run(
            ["g++", "-fsanitize=address,undefined",
             "-fno-omit-frame-pointer", "-g", "-O1", "-o", out, src],
            capture_output=True, text=True, timeout=60,
        )
        return _parse_compile_result(result, out)

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Compilation timed out", "binary_path": None}

    finally:
        try:
            os.unlink(src)
        except OSError:
            pass


def _parse_compile_result(result, out: str) -> dict:
    if result.returncode == 0:
        print("[compiler] ✅ Compilation succeeded")
        return {"success": True, "error": None, "binary_path": out}

    error_lines = [l for l in result.stderr.splitlines() if "error:" in l]
    first_error = error_lines[0] if error_lines else result.stderr[:400]
    print(f"[compiler] ❌ Failed: {first_error}")
    return {"success": False, "error": first_error, "binary_path": None}
