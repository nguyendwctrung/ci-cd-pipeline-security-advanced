from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional

import pandas as pd
from pymongo import DESCENDING, MongoClient


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
PIPELINE_STATUS_ORDER = ("COMPLETED", "BLOCKED", "ERROR")


def parse_timestamp(value: object) -> pd.Timestamp | None:
    """Convert an arbitrary stored timestamp into a UTC Pandas scalar."""
    parsed = pd.to_datetime(str(value), utc=True, errors="coerce")
    return parsed if isinstance(parsed, pd.Timestamp) else None


def severity_rows(findings: dict[str, int]) -> list[dict[str, int | str]]:
    """Return severity counts in descending risk order."""
    return [
        {"severity": severity, "findings": int(findings.get(severity, 0))}
        for severity in SEVERITY_ORDER
    ]


def load_runs(
    mongodb_uri: str,
    database: str,
    *,
    days: int = 30,
    limit: int = 500,
) -> list[Dict[str, Any]]:
    """Load sanitized monitoring runs from the dedicated database."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=3000)
    try:
        client.admin.command("ping")
        cursor = (
            client[database].security_runs
            .find({"run_started_at": {"$gte": since}}, {"_id": False})
            .sort("run_started_at", DESCENDING)
            .limit(limit)
        )
        return list(cursor)
    finally:
        client.close()


def load_findings(
    mongodb_uri: str,
    database: str,
    run_ids: list[str],
    *,
    limit: int = 50000,
) -> list[Dict[str, Any]]:
    """Load only approved sanitized finding fields for the selected runs."""
    if not run_ids:
        return []
    projection = {
        "_id": False,
        "run_id": True,
        "commit": True,
        "tool": True,
        "severity": True,
        "type": True,
        "message": True,
        "file": True,
        "line": True,
    }
    client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=3000)
    try:
        cursor = client[database].security_findings.find(
            {"run_id": {"$in": run_ids}}, projection
        ).limit(limit)
        return list(cursor)
    finally:
        client.close()


def filter_runs(
    runs: Iterable[Dict[str, Any]],
    *,
    status: Optional[str] = None,
    search: str = "",
) -> list[Dict[str, Any]]:
    query = search.strip().lower()
    filtered = []
    for run in runs:
        if status and status != "ALL" and run.get("pipeline_status") != status:
            continue
        searchable = " ".join((
            str(run.get("run_id", "")),
            str(run.get("github", {}).get("repository", "")),
            str(run.get("github", {}).get("ref", "")),
            str(run.get("git", {}).get("commit_sha", "")),
        )).lower()
        if query and query not in searchable:
            continue
        filtered.append(run)
    return filtered


def build_overview(runs: list[Dict[str, Any]]) -> Dict[str, Any]:
    latest = runs[0] if runs else None
    status_counts = {status: 0 for status in PIPELINE_STATUS_ORDER}
    for run in runs:
        current = run.get("pipeline_status")
        if current in status_counts:
            status_counts[current] += 1
    last_success = next(
        (run for run in runs if run.get("pipeline_status") == "COMPLETED"),
        None,
    )
    return {
        "latest": latest,
        "last_success": last_success,
        "status_counts": status_counts,
    }


def runs_frame(runs: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for run in runs:
        findings = run.get("findings_by_tool", {})
        rows.append({
            "run_id": str(run.get("run_id") or run.get("github", {}).get("run_id", "")),
            "started": parse_timestamp(run.get("run_started_at")),
            "status": run.get("pipeline_status", "UNKNOWN"),
            "decision": run.get("final_decision") or "UNAVAILABLE",
            "policy": run.get("policy_decision") or "UNAVAILABLE",
            "repository": run.get("github", {}).get("repository", "unknown"),
            "branch": run.get("github", {}).get("ref", "unknown"),
            "commit": run.get("git", {}).get("commit_sha", run.get("github", {}).get("sha", "unknown")),
            "duration_seconds": float(run.get("duration_seconds", 0)),
            "findings": sum(int(value) for value in findings.values()),
            "high": int(run.get("findings_by_severity", {}).get("HIGH", 0)),
            "critical": int(run.get("findings_by_severity", {}).get("CRITICAL", 0)),
            "gemini_available": bool(run.get("llm_available")),
            "run_url": run.get("github", {}).get("run_url"),
        })
    return pd.DataFrame(rows)


def stage_frame(run: Dict[str, Any]) -> pd.DataFrame:
    return pd.DataFrame([
        {
            "stage": name.replace("_", " ").title(),
            "status": stage.get("status", "UNKNOWN"),
            "duration_seconds": float(stage.get("duration_seconds", 0)),
            "error": stage.get("error") or "",
        }
        for name, stage in run.get("stages", {}).items()
    ])


def findings_frame(findings: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    columns = ["severity", "tool", "type", "message", "file", "line", "commit", "run_id"]
    rows = []
    for finding in findings:
        rows.append({
            "severity": finding.get("severity", "UNKNOWN"),
            "tool": finding.get("tool", "unknown"),
            "type": finding.get("type", "unknown"),
            "message": finding.get("message", ""),
            "file": finding.get("file") or "N/A",
            "line": finding.get("line") or "N/A",
            "commit": finding.get("commit", "unknown"),
            "run_id": str(finding.get("run_id", "")),
        })
    return pd.DataFrame(rows, columns=columns)


def filter_findings(
    frame: pd.DataFrame,
    *,
    run_id: str = "ALL",
    severity: str = "ALL",
    tool: str = "ALL",
    finding_type: str = "",
    file: str = "",
    search: str = "",
) -> pd.DataFrame:
    filtered = frame.copy()
    if run_id != "ALL":
        filtered = filtered[filtered["run_id"] == run_id]
    if severity != "ALL":
        filtered = filtered[filtered["severity"] == severity]
    if tool != "ALL":
        filtered = filtered[filtered["tool"] == tool]
    for column, value in (("type", finding_type), ("file", file)):
        if value.strip():
            filtered = filtered[filtered[column].astype(str).str.contains(value.strip(), case=False, regex=False)]
    if search.strip():
        query = search.strip()
        searchable = filtered[["type", "message", "file", "commit", "run_id"]].astype(str).agg(" ".join, axis=1)
        filtered = filtered[searchable.str.contains(query, case=False, regex=False)]
    return filtered
