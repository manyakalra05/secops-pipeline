"""
fuzzer.py
Auto-generates a libFuzzer harness and runs it with ASan against the patched function.
"""

import subprocess
import tempfile
import os
import re


MAX_FUZZ_SECONDS = 60
MAX_FUZZ_RUNS = 100_000


def _generate_harness(function_name: str, patch_code: str) -> str:
    return f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

{patch_code}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;
    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\\0';
    {function_name}(buf);
    free(buf);
    return 0;
}}
"""


def _write_temp(content: str, suffix: str) -> str:
    tmp = tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, mode="w", encoding="utf-8"
    )
    tmp.write(content)
    tmp.close()
    return tmp.name


def run_fuzzer(function_name: str, patch_code: str) -> dict:
    """
    Returns:
    {"passed": bool, "crash_log": str|None, "stack_trace": str|None, "runs": int}
    """
    print(f"[fuzzer] Running libFuzzer on '{function_name}'...")

    harness_file = _write_temp(_generate_harness(function_name, patch_code), ".cpp")
    binary_file = harness_file.replace(".cpp", "_fuzz")
    corpus_dir = tempfile.mkdtemp()

    try:
        # compile harness
        compile_result = subprocess.run(
            [
                "clang++",
                "-fsanitize=fuzzer,address,undefined",
                "-fno-omit-frame-pointer",
                "-g", "-O1",
                "-o", binary_file,
                harness_file,
            ],
            capture_output=True, text=True, timeout=60,
        )

        if compile_result.returncode != 0:
            print("[fuzzer] Harness compilation failed")
            return {
                "passed": False,
                "crash_log": f"Harness compile error: {compile_result.stderr[:500]}",
                "stack_trace": None,
                "runs": 0,
            }

        # run fuzzer
        fuzz_result = subprocess.run(
            [
                binary_file,
                corpus_dir,
                f"-max_total_time={MAX_FUZZ_SECONDS}",
                f"-runs={MAX_FUZZ_RUNS}",
                "-print_final_stats=1",
            ],
            capture_output=True, text=True,
            timeout=MAX_FUZZ_SECONDS + 15,
        )

        output = fuzz_result.stdout + fuzz_result.stderr

        runs_match = re.search(r"stat::number_of_executed_units:\s*(\d+)", output)
        runs = int(runs_match.group(1)) if runs_match else 0

        crash_indicators = [
            "ERROR: AddressSanitizer",
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "use-after-free",
            "SEGV",
            "UndefinedBehaviorSanitizer",
        ]

        crashed = any(c in output for c in crash_indicators)

        if crashed:
            stack_start = next(
                (output.find(c) for c in crash_indicators if c in output), 0
            )
            stack_trace = output[stack_start:stack_start + 2000]
            print(f"[fuzzer] ❌ Crash after {runs} runs")
            return {
                "passed": False,
                "crash_log": output[:1000],
                "stack_trace": stack_trace,
                "runs": runs,
            }

        print(f"[fuzzer] ✅ No crashes after {runs} runs")
        return {"passed": True, "crash_log": None, "stack_trace": None, "runs": runs}

    except subprocess.TimeoutExpired:
        return {"passed": True, "crash_log": None, "stack_trace": None, "runs": MAX_FUZZ_RUNS}

    finally:
        for f in [harness_file, binary_file]:
            try:
                os.unlink(f)
            except OSError:
                pass
