"""Data models used by the benchmark runner and scorer."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class RepoSpec:
    """Pinned benchmark repository metadata."""

    name: str
    url: str
    commit: str
    language: str
    category: str
    enabled_checks: list[str]
    ground_truth: Optional[str] = None
    timeout_seconds: int = 900

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RepoSpec":
        required = ("name", "url", "commit", "language", "category", "enabled_checks")
        missing = [field for field in required if field not in data]
        if missing:
            raise ValueError(f"Repository entry is missing required fields: {', '.join(missing)}")
        if not isinstance(data["enabled_checks"], list) or not data["enabled_checks"]:
            raise ValueError(f"{data.get('name', '<unknown>')}: enabled_checks must be a non-empty list")
        commit = str(data["commit"])
        if len(commit) != 40 or any(char not in "0123456789abcdefABCDEF" for char in commit):
            raise ValueError(f"{data.get('name', '<unknown>')}: commit must be a 40-character SHA")
        return cls(
            name=str(data["name"]),
            url=str(data["url"]),
            commit=commit.lower(),
            language=str(data["language"]),
            category=str(data["category"]),
            enabled_checks=[str(item) for item in data["enabled_checks"]],
            ground_truth=str(data["ground_truth"]) if data.get("ground_truth") else None,
            timeout_seconds=int(data.get("timeout_seconds", 900)),
        )


@dataclass(frozen=True)
class BenchmarkPaths:
    """Resolved benchmark directory layout."""

    root: Path
    repos_yaml: Path
    ground_truth_dir: Path
    workdir: Path
    repo_workdir: Path
    results_dir: Path
    raw_dir: Path
    normalized_dir: Path
    scored_dir: Path

    @classmethod
    def from_root(cls, root: Path) -> "BenchmarkPaths":
        root = root.resolve()
        return cls(
            root=root,
            repos_yaml=root / "repos.yaml",
            ground_truth_dir=root / "ground-truth",
            workdir=root / "workdir",
            repo_workdir=root / "workdir" / "repos",
            results_dir=root / "results",
            raw_dir=root / "results" / "raw",
            normalized_dir=root / "results" / "normalized",
            scored_dir=root / "results" / "scored",
        )


@dataclass(frozen=True)
class BenchmarkFinding:
    """Normalized finding schema for benchmark scoring."""

    repo: str
    tool: str
    rule_id: str
    category: str
    cwe: Optional[str]
    severity: str
    file: Optional[str]
    line: Optional[int]
    message: str
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "tool": self.tool,
            "rule_id": self.rule_id,
            "category": self.category,
            "cwe": self.cwe,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "confidence": self.confidence,
        }

