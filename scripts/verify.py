#!/usr/bin/env python3
"""Run meaningful local tests and persist the observed result as JSON."""
import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    start = time.perf_counter()
    output = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    log = output.getvalue()
    artifacts = ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)
    (artifacts / "test_output.txt").write_text(log, encoding="utf-8", newline="\n")
    report = {
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "tests_run": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "successful": result.wasSuccessful(), "runtime_seconds": round(time.perf_counter() - start, 3),
        "suite": "unittest discovery: behavior, acquisition, matcher, gateway, application HTTP integration",
        "network_scope": "local loopback receiver only; no external AI request",
        "benchmark_performance_is_separate": True,
    }
    (artifacts / "test_summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2))
    if not result.wasSuccessful():
        print(log)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
