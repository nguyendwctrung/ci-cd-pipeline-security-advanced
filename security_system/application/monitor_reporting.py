"""Publish and render sanitized pipeline monitoring reports."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any


def render_markdown(report: dict) -> str:
    findings = report.get("findings_by_severity", {})
    scanners = report.get("scanner_health", {})
    rows = "\n".join(
        f"| {name} | {details.get('status', 'UNKNOWN')} |"
        for name, details in scanners.items()
    )
    return f"""## Security Pipeline Monitor

| Metric | Result |
|---|---|
| Pipeline status | **{report.get('pipeline_status', 'ERROR')}** |
| Final decision | **{report.get('final_decision') or 'Unavailable'}** |
| Policy decision | {report.get('policy_decision') or 'Unavailable'} |
| Duration | {report.get('duration_seconds', 0)} seconds |
| Critical findings | {findings.get('CRITICAL', 0)} |
| High findings | {findings.get('HIGH', 0)} |
| Gemini available | {'Yes' if report.get('llm_available') else 'No'} |

### Scanner Health

| Scanner | Status |
|---|---|
{rows or '| No scanner data | UNKNOWN |'}
"""


def publish_report(path: Path, url: str, secret: str) -> Any:
    import requests

    body = path.read_bytes()
    timestamp = str(int(time.time()))
    signature = hmac.new(
        secret.encode(),
        timestamp.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    response = requests.post(
        f"{url.rstrip('/')}/api/v1/runs",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Monitor-Timestamp": timestamp,
            "X-Monitor-Signature": signature,
        },
        timeout=15,
    )
    response.raise_for_status()
    return response


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    summary = subparsers.add_parser("summary")
    summary.add_argument("report", type=Path)
    publish = subparsers.add_parser("publish")
    publish.add_argument("report", type=Path)
    publish.add_argument("--url", required=True)
    publish.add_argument("--secret", required=True)
    args = parser.parse_args()

    if args.command == "summary":
        print(render_markdown(json.loads(args.report.read_text(encoding="utf-8"))))
    else:
        response = publish_report(args.report, args.url, args.secret)
        print(f"Monitoring report accepted ({response.status_code})")


if __name__ == "__main__":
    main()
