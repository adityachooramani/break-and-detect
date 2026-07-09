#!/usr/bin/env python3
"""Convert an OWASP ZAP baseline JSON report to SARIF 2.1.0."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


def risk_to_level(riskcode: str) -> str:
    """Map ZAP risk codes to SARIF levels (3/4 -> error, else warning)."""
    if riskcode in {"3", "4"}:
        return "error"
    return "warning"


def _physical_location(uri: str, method: str = "", param: str = "") -> dict[str, Any]:
    parsed = urlparse(uri)
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri or "unknown"},
        }
    }
    if parsed.scheme in {"http", "https"}:
        location["physicalLocation"]["artifactLocation"]["uriBaseId"] = "WEBROOT"
    if method or param:
        location["properties"] = {
            k: v for k, v in (("method", method), ("parameter", param)) if v
        }
    return location


def alert_to_result(alert: dict[str, Any]) -> dict[str, Any]:
    """Convert one ZAP alert (with zero or more instances) to a SARIF result."""
    plugin_id = str(alert.get("pluginid") or alert.get("alertRef") or "unknown")
    name = alert.get("name") or alert.get("alert") or plugin_id
    riskcode = str(alert.get("riskcode", "0"))
    desc = (alert.get("desc") or "").strip()
    solution = (alert.get("solution") or "").strip()
    message_parts = [name]
    if desc:
        message_parts.append(desc)
    if solution:
        message_parts.append(f"Solution: {solution}")

    result: dict[str, Any] = {
        "ruleId": plugin_id,
        "level": risk_to_level(riskcode),
        "message": {"text": "\n\n".join(message_parts)},
        "properties": {
            "riskcode": riskcode,
            "riskdesc": alert.get("riskdesc", ""),
            "confidence": alert.get("confidence", ""),
            "cweid": alert.get("cweid", ""),
            "wascid": alert.get("wascid", ""),
        },
    }

    instances = alert.get("instances")
    if not isinstance(instances, list):
        instances = []

    locations: list[dict[str, Any]] = []
    for instance in instances:
        if not isinstance(instance, dict):
            continue
        uri = str(instance.get("uri") or "").strip()
        method = str(instance.get("method") or "").strip()
        param = str(instance.get("param") or "").strip()
        loc = _physical_location(uri, method, param)
        evidence = str(instance.get("evidence") or "").strip()
        otherinfo = str(instance.get("otherinfo") or "").strip()
        if evidence or otherinfo:
            loc["properties"] = {
                **loc.get("properties", {}),
                **{k: v for k, v in (("evidence", evidence), ("otherinfo", otherinfo)) if v},
            }
        locations.append(loc)

    if locations:
        result["locations"] = locations
    else:
        # Alert with no instances: still emit a result with site-level context.
        result["locations"] = [_physical_location("unknown")]

    return result


def convert_zap_to_sarif(zap_data: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from ZAP baseline JSON."""
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}

    for site in zap_data.get("site", []):
        if not isinstance(site, dict):
            continue
        for alert in site.get("alerts", []):
            if not isinstance(alert, dict):
                continue
            result = alert_to_result(alert)
            results.append(result)

            plugin_id = result["ruleId"]
            if plugin_id not in rules:
                rules[plugin_id] = {
                    "id": plugin_id,
                    "name": alert.get("name") or alert.get("alert") or plugin_id,
                    "shortDescription": {
                        "text": alert.get("name") or alert.get("alert") or plugin_id
                    },
                    "helpUri": alert.get("reference") or None,
                    "properties": {
                        "tags": ["security", "zap"],
                    },
                }
                if not rules[plugin_id]["helpUri"]:
                    del rules[plugin_id]["helpUri"]

    tool_version = str(zap_data.get("@version", ""))
    driver: dict[str, Any] = {
        "name": "OWASP ZAP",
        "informationUri": "https://www.zaproxy.org/",
        "rules": list(rules.values()),
    }
    if tool_version:
        driver["version"] = tool_version

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": driver},
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="ZAP baseline JSON report")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Output SARIF file path",
    )
    args = parser.parse_args()

    if not args.input.is_file():
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 1

    try:
        zap_data = json.loads(args.input.read_text())
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {args.input}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(zap_data, dict):
        print(f"error: expected JSON object in {args.input}", file=sys.stderr)
        return 1

    sarif = convert_zap_to_sarif(zap_data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(sarif, indent=2) + "\n")
    print(f"Wrote {len(sarif['runs'][0]['results'])} result(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
