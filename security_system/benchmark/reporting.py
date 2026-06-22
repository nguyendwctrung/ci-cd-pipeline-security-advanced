"""Generate benchmark summary reports."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from security_system.benchmark.models import BenchmarkPaths, RepoSpec

SUMMARY_FIELDS = [
    "repo",
    "language",
    "category",
    "enabled_checks",
    "timeout_seconds",
    "status",
    "duration_seconds",
    "finding_count",
    "ground_truth",
    "error_stage",
    "error_reason",
    "strict_precision",
    "strict_recall",
    "strict_f1",
    "relaxed_precision",
    "relaxed_recall",
    "relaxed_f1",
    "category_precision",
    "category_recall",
    "category_f1",
]


def generate_summary(paths: BenchmarkPaths, repos: list[RepoSpec]) -> Path:
    """Write benchmark/results/summary.csv from run and score outputs."""
    rows: list[dict[str, Any]] = []
    for repo in repos:
        run = _load_json(paths.results_dir / "runs" / f"{repo.name}.json")
        score = _load_json(paths.scored_dir / f"{repo.name}.score.json")
        rows.append({
            "repo": repo.name,
            "language": repo.language,
            "category": repo.category,
            "enabled_checks": ",".join(repo.enabled_checks),
            "timeout_seconds": repo.timeout_seconds,
            "status": run.get("status", "NOT_RUN"),
            "duration_seconds": run.get("duration_seconds", ""),
            "finding_count": run.get("finding_count", ""),
            "ground_truth": repo.ground_truth or "",
            "error_stage": run.get("stage", ""),
            "error_reason": run.get("error") or run.get("reason", ""),
            "strict_precision": score.get("strict", {}).get("precision", ""),
            "strict_recall": score.get("strict", {}).get("recall", ""),
            "strict_f1": score.get("strict", {}).get("f1", ""),
            "relaxed_precision": score.get("relaxed", {}).get("precision", ""),
            "relaxed_recall": score.get("relaxed", {}).get("recall", ""),
            "relaxed_f1": score.get("relaxed", {}).get("f1", ""),
            "category_precision": score.get("category", {}).get("precision", ""),
            "category_recall": score.get("category", {}).get("recall", ""),
            "category_f1": score.get("category", {}).get("f1", ""),
        })
    path = paths.results_dir / "summary.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}
