"""Score benchmark findings against CSV ground truth."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class GroundTruthFinding:
    """One expected vulnerability from a ground-truth CSV file."""

    repo: str
    vuln_id: str
    type: str
    cwe: Optional[str]
    file: Optional[str]
    line: Optional[int]
    severity: Optional[str]


def score_repository(findings_path: Path, ground_truth_path: Path) -> dict[str, Any]:
    """Score one normalized findings file against one ground-truth CSV."""
    findings = _load_findings(findings_path)
    expected = load_ground_truth(ground_truth_path)
    return {
        "repo": findings[0]["repo"] if findings else (expected[0].repo if expected else findings_path.stem.replace(".findings", "")),
        "ground_truth": str(ground_truth_path),
        "findings": len(findings),
        "expected": len(expected),
        "strict": _score_mode(findings, expected, _strict_match),
        "relaxed": _score_mode(findings, expected, _relaxed_match),
        "category": _score_mode(findings, expected, _category_match),
    }


def load_ground_truth(path: Path) -> list[GroundTruthFinding]:
    """Load expected vulnerabilities from CSV."""
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    expected: list[GroundTruthFinding] = []
    for row in rows:
        if not any((value or "").strip() for value in row.values()):
            continue
        expected.append(GroundTruthFinding(
            repo=(row.get("repo") or "").strip(),
            vuln_id=(row.get("vuln_id") or "").strip(),
            type=(row.get("type") or row.get("expected_category") or "").strip(),
            cwe=_blank_to_none(row.get("cwe")),
            file=_blank_to_none(row.get("file")),
            line=_parse_int(row.get("line")),
            severity=_blank_to_none(row.get("severity")),
        ))
    return expected


def write_score(path: Path, score: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(score, indent=2), encoding="utf-8")


def _load_findings(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON array")
    return [finding for finding in data if isinstance(finding, dict)]


def _score_mode(
    findings: list[dict[str, Any]],
    expected: list[GroundTruthFinding],
    matcher: Callable[[dict[str, Any], GroundTruthFinding], bool],
) -> dict[str, float | int]:
    matched_findings: set[int] = set()
    matched_expected: set[int] = set()
    for expected_index, truth in enumerate(expected):
        for finding_index, finding in enumerate(findings):
            if finding_index in matched_findings:
                continue
            if matcher(finding, truth):
                matched_findings.add(finding_index)
                matched_expected.add(expected_index)
                break
    tp = len(matched_expected)
    fp = len(findings) - len(matched_findings)
    fn = len(expected) - len(matched_expected)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _strict_match(finding: dict[str, Any], truth: GroundTruthFinding) -> bool:
    if not _relaxed_match(finding, truth):
        return False
    if truth.line is None or finding.get("line") is None:
        return False
    return abs(int(finding["line"]) - truth.line) <= 5


def _relaxed_match(finding: dict[str, Any], truth: GroundTruthFinding) -> bool:
    return _same_text(finding.get("cwe"), truth.cwe) and _same_path(finding.get("file"), truth.file)


def _category_match(finding: dict[str, Any], truth: GroundTruthFinding) -> bool:
    return _same_text(finding.get("category"), truth.type) or _same_text(finding.get("rule_id"), truth.type)


def _same_text(left: Any, right: Any) -> bool:
    return bool(left and right and str(left).strip().lower() == str(right).strip().lower())


def _same_path(left: Any, right: Any) -> bool:
    if not left or not right:
        return False
    return str(left).replace("\\", "/").strip().lower() == str(right).replace("\\", "/").strip().lower()


def _blank_to_none(value: Optional[str]) -> Optional[str]:
    value = (value or "").strip()
    return value or None


def _parse_int(value: Optional[str]) -> Optional[int]:
    value = (value or "").strip()
    return int(value) if value else None

