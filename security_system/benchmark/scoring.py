"""Score benchmark findings against CSV ground truth."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional


@dataclass(frozen=True)
class GroundTruthFinding:
    """One expected vulnerability from a ground-truth CSV file."""

    repo: str
    category: str
    tool: Optional[str]
    rule_id: Optional[str]
    cwe: Optional[str]
    file: Optional[str]
    line: Optional[int]
    severity: Optional[str]
    message: Optional[str]
    confidence: Optional[str]


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
        row = _normalize_ground_truth_row(row)
        expected.append(GroundTruthFinding(
            repo=(row.get("repo") or "").strip(),
            category=(row.get("category") or row.get("type") or row.get("expected_category") or "").strip(),
            tool=_blank_to_none(row.get("tool")),
            rule_id=_blank_to_none(row.get("rule_id")),
            cwe=_blank_to_none(row.get("cwe")),
            file=_blank_to_none(row.get("file")),
            line=_parse_int(row.get("line")),
            severity=_blank_to_none(row.get("severity")),
            message=_blank_to_none(row.get("message") or row.get("vuln_id")),
            confidence=_blank_to_none(row.get("confidence")),
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
    index = _FindingIndex(findings)
    matched_findings: set[int] = set()
    matched_expected: set[int] = set()
    for expected_index, truth in enumerate(expected):
        for finding_index in index.candidates(truth, matcher):
            if finding_index in matched_findings:
                continue
            finding = findings[finding_index]
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


class _FindingIndex:
    """Lookup finding candidates while preserving original greedy match order."""

    def __init__(self, findings: list[dict[str, Any]]) -> None:
        self._all = list(range(len(findings)))
        self._by_rule_file: dict[tuple[str, str], list[int]] = defaultdict(list)
        self._by_cwe_file: dict[tuple[str, str], list[int]] = defaultdict(list)
        self._by_category: dict[str, list[int]] = defaultdict(list)
        self._by_rule: dict[str, list[int]] = defaultdict(list)
        for index, finding in enumerate(findings):
            rule = _normalize_text(finding.get("rule_id"))
            cwe = _normalize_text(finding.get("cwe"))
            category = _normalize_text(finding.get("category"))
            file_path = _normalize_path(finding.get("file"))
            if rule and file_path:
                self._by_rule_file[(rule, file_path)].append(index)
            if cwe and file_path:
                self._by_cwe_file[(cwe, file_path)].append(index)
            if category:
                self._by_category[category].append(index)
            if rule:
                self._by_rule[rule].append(index)

    def candidates(
        self,
        truth: GroundTruthFinding,
        matcher: Callable[[dict[str, Any], GroundTruthFinding], bool],
    ) -> list[int]:
        if matcher is _strict_match or matcher is _relaxed_match:
            if truth.rule_id:
                key = (_normalize_text(truth.rule_id), _normalize_path(truth.file))
                return list(self._by_rule_file.get(key, []))
            key = (_normalize_text(truth.cwe), _normalize_path(truth.file))
            return list(self._by_cwe_file.get(key, []))
        if matcher is _category_match:
            return _merge_ordered(
                self._by_category.get(_normalize_text(truth.category), []),
                self._by_rule.get(_normalize_text(truth.category), []),
                self._by_rule.get(_normalize_text(truth.rule_id), []),
            )
        return self._all


def _merge_ordered(*groups: Iterable[int]) -> list[int]:
    seen: set[int] = set()
    merged: list[int] = []
    for index in sorted({index for group in groups for index in group}):
        if index not in seen:
            seen.add(index)
            merged.append(index)
    return merged


def _strict_match(finding: dict[str, Any], truth: GroundTruthFinding) -> bool:
    if truth.rule_id:
        if not _same_text(finding.get("rule_id"), truth.rule_id):
            return False
        if not _same_path(finding.get("file"), truth.file):
            return False
    elif not _relaxed_match(finding, truth):
        return False
    if truth.line is None or finding.get("line") is None:
        return bool(truth.rule_id)
    return abs(int(finding["line"]) - truth.line) <= 5


def _relaxed_match(finding: dict[str, Any], truth: GroundTruthFinding) -> bool:
    if truth.rule_id:
        return _same_text(finding.get("rule_id"), truth.rule_id) and _same_path(finding.get("file"), truth.file)
    return _same_text(finding.get("cwe"), truth.cwe) and _same_path(finding.get("file"), truth.file)


def _category_match(finding: dict[str, Any], truth: GroundTruthFinding) -> bool:
    return (
        _same_text(finding.get("category"), truth.category)
        or _same_text(finding.get("rule_id"), truth.category)
        or _same_text(finding.get("rule_id"), truth.rule_id)
    )


def _same_text(left: Any, right: Any) -> bool:
    return bool(left and right and str(left).strip().lower() == str(right).strip().lower())


def _same_path(left: Any, right: Any) -> bool:
    return bool(_normalize_path(left) and _normalize_path(left) == _normalize_path(right))


def _normalize_text(value: Any) -> str:
    return str(value).strip().lower() if value else ""


def _normalize_path(value: Any) -> str:
    return str(value).replace("\\", "/").strip().lower() if value else ""


def _blank_to_none(value: Optional[str]) -> Optional[str]:
    value = (value or "").strip()
    return value or None


def _parse_int(value: Optional[str]) -> Optional[int]:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _normalize_ground_truth_row(row: Mapping[Any, Any]) -> dict[str, Any]:
    """Recover rows appended with the new schema under the old CSV header."""
    extra = row.get(None)
    if extra and "rule_id" not in row:
        extras = list(extra) if isinstance(extra, list) else [extra]
        return {
            "repo": row.get("repo"),
            "vuln_id": row.get("vuln_id"),
            "type": row.get("type"),
            "rule_id": row.get("cwe"),
            "cwe": row.get("file"),
            "file": row.get("line"),
            "line": row.get("severity"),
            "severity": extras[0] if extras else "",
        }
    return {str(key): value for key, value in row.items() if key is not None}
