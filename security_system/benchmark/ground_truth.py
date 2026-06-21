"""Utilities for seeding ground-truth CSV files from normalized findings."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, TypedDict

from security_system.benchmark.models import RepoSpec

GROUND_TRUTH_FIELDS: list[str] = ["repo", "vuln_id", "type", "rule_id", "cwe", "file", "line", "severity"]


class GroundTruthRow(TypedDict):
    """CSV row shape for benchmark ground truth."""

    repo: str
    vuln_id: str
    type: str
    rule_id: str
    cwe: str
    file: str
    line: str
    severity: str


@dataclass(frozen=True)
class SeedResult:
    """Result of seeding one ground-truth CSV."""

    repo: str
    path: Path
    candidates: int
    added: int
    skipped_existing: int
    written: bool


def seed_ground_truth_from_findings(
    repo: RepoSpec,
    findings_path: Path,
    ground_truth_dir: Path,
    *,
    write: bool = False,
    limit: Optional[int] = None,
) -> SeedResult:
    """Append scanner-derived candidate rows to a repo ground-truth CSV."""
    if not repo.ground_truth:
        raise ValueError(f"{repo.name} has no ground_truth file configured")
    findings = _load_findings(findings_path)
    if limit is not None:
        findings = findings[:limit]
    ground_truth_path = ground_truth_dir / repo.ground_truth
    existing = _existing_keys(ground_truth_path)
    rows: list[GroundTruthRow] = []
    skipped = 0
    for index, finding in enumerate(findings, start=1):
        row = _finding_to_ground_truth_row(repo.name, index, finding)
        key = _row_key(row)
        if key in existing:
            skipped += 1
            continue
        rows.append(row)
        existing.add(key)
    if write and rows:
        _append_rows(ground_truth_path, rows)
    return SeedResult(
        repo=repo.name,
        path=ground_truth_path,
        candidates=len(findings),
        added=len(rows),
        skipped_existing=skipped,
        written=write,
    )


def _load_findings(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON array")
    return [item for item in data if isinstance(item, dict)]


def _finding_to_ground_truth_row(repo_name: str, index: int, finding: dict[str, Any]) -> GroundTruthRow:
    return {
        "repo": repo_name,
        "vuln_id": f"{repo_name.upper().replace('-', '_')}-CANDIDATE-{index:04d}",
        "type": str(finding.get("category") or finding.get("rule_id") or ""),
        "rule_id": str(finding.get("rule_id") or ""),
        "cwe": str(finding.get("cwe") or _default_cwe_for_category(finding.get("category")) or ""),
        "file": str(finding.get("file") or ""),
        "line": "" if finding.get("line") is None else str(finding.get("line")),
        "severity": str(finding.get("severity") or ""),
    }


def _default_cwe_for_category(category: Any) -> Optional[str]:
    return {
        "secret": "CWE-798",
        "sql-injection": "CWE-89",
        "xss": "CWE-79",
        "command-injection": "CWE-78",
    }.get(str(category or "").lower())


def _existing_keys(path: Path) -> set[tuple[str, str, str, str, str]]:
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return {_row_key(_normalize_existing_row(row)) for row in reader if row}


def _row_key(row: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(row.get("type") or "").strip().lower(),
        str(row.get("rule_id") or "").strip().lower(),
        str(row.get("cwe") or "").strip().lower(),
        str(row.get("file") or "").replace("\\", "/").strip().lower(),
        str(row.get("line") or "").strip(),
    )


def _append_rows(path: Path, rows: list[GroundTruthRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not path.exists() or path.stat().st_size == 0
    if path.exists() and path.stat().st_size > 0 and _needs_schema_rewrite(path):
        existing_rows = _read_existing_rows(path)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=GROUND_TRUTH_FIELDS)
            writer.writeheader()
            writer.writerows([dict(row) for row in existing_rows + rows])
        return
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=GROUND_TRUTH_FIELDS)
        if needs_header:
            writer.writeheader()
        writer.writerows([dict(row) for row in rows])


def _needs_schema_rewrite(path: Path) -> bool:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != GROUND_TRUTH_FIELDS:
            return True
        return any(None in row for row in reader)


def _read_existing_rows(path: Path) -> list[GroundTruthRow]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [_normalize_existing_row(row) for row in reader if row and _row_has_values(row)]


def _normalize_existing_row(row: Mapping[Any, Any]) -> GroundTruthRow:
    extra = row.get(None)
    if extra and "rule_id" not in row:
        extras = list(extra) if isinstance(extra, list) else [extra]
        return {
            "repo": str(row.get("repo") or ""),
            "vuln_id": str(row.get("vuln_id") or ""),
            "type": str(row.get("type") or ""),
            "rule_id": str(row.get("cwe") or ""),
            "cwe": str(row.get("file") or ""),
            "file": str(row.get("line") or ""),
            "line": str(row.get("severity") or ""),
            "severity": str(extras[0] if extras else ""),
        }
    return {
        "repo": str(row.get("repo") or ""),
        "vuln_id": str(row.get("vuln_id") or ""),
        "type": str(row.get("type") or ""),
        "rule_id": str(row.get("rule_id") or ""),
        "cwe": str(row.get("cwe") or ""),
        "file": str(row.get("file") or ""),
        "line": str(row.get("line") or ""),
        "severity": str(row.get("severity") or ""),
    }


def _row_has_values(row: Mapping[Any, Any]) -> bool:
    for value in row.values():
        if isinstance(value, list):
            if any(str(item).strip() for item in value):
                return True
        elif str(value or "").strip():
            return True
    return False