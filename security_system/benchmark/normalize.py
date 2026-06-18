"""Convert existing scanner output into benchmark finding records."""

from __future__ import annotations

import re
from typing import Any, Optional

from security_system.application.use_cases.run_scan import ScanOutput
from security_system.benchmark.models import BenchmarkFinding
from security_system.domain.models import SecurityIssue

_CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)


def normalize_scan_output(repo_name: str, scan_output: ScanOutput) -> list[BenchmarkFinding]:
    """Map existing normalized issues into benchmark-normalized findings."""
    semgrep_cwes = _semgrep_cwe_lookup(scan_output.raw_data.get("semgrep", []))
    findings: list[BenchmarkFinding] = []
    for issue in scan_output.all_issues:
        findings.append(issue_to_benchmark_finding(repo_name, issue, semgrep_cwes.get(_issue_key(issue))))
    return findings


def issue_to_benchmark_finding(
    repo_name: str,
    issue: SecurityIssue,
    cwe: Optional[str] = None,
) -> BenchmarkFinding:
    """Convert a SecurityIssue into the benchmark schema."""
    return BenchmarkFinding(
        repo=repo_name,
        tool=issue.tool,
        rule_id=issue.type,
        category=infer_category(issue),
        cwe=cwe,
        severity=issue.severity.value,
        file=issue.file,
        line=issue.line,
        message=issue.message,
        confidence="medium",
    )


def infer_category(issue: SecurityIssue) -> str:
    """Infer a broad benchmark category from tool and rule identifiers."""
    tool = issue.tool.lower()
    rule = issue.type.lower()
    if tool == "gitleaks" or "secret" in rule or "credential" in rule or "token" in rule:
        return "secret"
    if tool == "trivy":
        if rule.startswith("cve-"):
            return "dependency"
        return "iac"
    if "sql" in rule:
        return "sql-injection"
    if "xss" in rule or "cross-site" in rule:
        return "xss"
    if "command" in rule or "exec" in rule:
        return "command-injection"
    if "docker" in rule or "kubernetes" in rule or "k8s" in rule:
        return "iac"
    return "sast" if tool == "semgrep" else tool


def _semgrep_cwe_lookup(results: list[Any]) -> dict[tuple[str, Optional[str], Optional[int]], str]:
    lookup: dict[tuple[str, Optional[str], Optional[int]], str] = {}
    for result in results:
        if not isinstance(result, dict):
            continue
        rule_id = str(result.get("check_id", "unknown-rule"))
        path = result.get("path")
        line = result.get("start", {}).get("line") if isinstance(result.get("start"), dict) else None
        cwe = _extract_cwe(result.get("extra", {}).get("metadata", {}))
        if cwe:
            lookup[(rule_id, path, line)] = cwe
    return lookup


def _issue_key(issue: SecurityIssue) -> tuple[str, Optional[str], Optional[int]]:
    return (issue.type, issue.file, issue.line)


def _extract_cwe(metadata: Any) -> Optional[str]:
    if isinstance(metadata, dict):
        for key in ("cwe", "cwe_id", "cwe-id"):
            cwe = _extract_cwe(metadata.get(key))
            if cwe:
                return cwe
        for value in metadata.values():
            cwe = _extract_cwe(value)
            if cwe:
                return cwe
    if isinstance(metadata, list):
        for value in metadata:
            cwe = _extract_cwe(value)
            if cwe:
                return cwe
    if isinstance(metadata, str):
        match = _CWE_PATTERN.search(metadata)
        if match:
            return match.group(0).upper()
    return None

