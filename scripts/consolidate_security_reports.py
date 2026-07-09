#!/usr/bin/env python3
"""Consolidate scan outputs and fail on missing reports or high severity findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def count_sarif_errors(path: Path) -> int:
    data = json.loads(path.read_text())
    return sum(
        1
        for run in data.get("runs", [])
        for result in run.get("results", [])
        if result.get("level") == "error"
    )


def count_zap_highs(path: Path) -> int:
    data = json.loads(path.read_text())
    count = 0
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = str(alert.get("riskdesc", alert.get("risk", ""))).lower()
            if risk.startswith("high"):
                count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expect", nargs="+", required=True)
    args = parser.parse_args()

    report_root = Path(args.input_dir)
    output_path = Path(args.output)

    rows = []
    failures = []

    for expected_name in args.expect:
        report_path = report_root / expected_name
        if not report_path.exists() or report_path.stat().st_size == 0:
            failures.append(f"missing or empty report: {expected_name}")
            rows.append((expected_name, "missing", "FAIL"))
            continue

        if report_path.suffix == ".sarif":
            high_count = count_sarif_errors(report_path)
            rows.append((expected_name, str(high_count), "FAIL" if high_count else "PASS"))
            if high_count:
                failures.append(f"{expected_name}: {high_count} error-level result(s)")
        elif report_path.name == "zap.json":
            high_count = count_zap_highs(report_path)
            rows.append((expected_name, str(high_count), "FAIL" if high_count else "PASS"))
            if high_count:
                failures.append(f"{expected_name}: {high_count} high-risk alert(s)")
        else:
            rows.append((expected_name, "present", "PASS"))

    lines = [
        "# Consolidated Security Report",
        "",
        "| Report | High/Critical count | Result |",
        "| --- | ---: | --- |",
    ]
    for name, count, result in rows:
        lines.append(f"| {name} | {count} | {result} |")

    lines.append("")
    if failures:
        lines.append("The gate failed on the following issues:")
        lines.extend(f"- {item}" for item in failures)
    else:
        lines.append("No missing reports or high/critical findings were detected.")

    output_path.write_text("\n".join(lines) + "\n")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())