"""Benchmark runner orchestration."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from security_system.application.use_cases.run_scan import load_scan_output
from security_system.application.use_cases.run_scan import REPORT_PATHS 
from security_system.benchmark.baselines import run_baseline_stubs
from security_system.benchmark.models import BenchmarkPaths, RepoSpec
from security_system.benchmark.normalize import normalize_scan_output
from security_system.benchmark.repository import RepositoryManager


class BenchmarkRunner:
    """Run the current security system across pinned repositories."""

    def __init__(self, paths: BenchmarkPaths) -> None:
        self.paths = paths
        self.repo_manager = RepositoryManager(paths.repo_workdir)
        for directory in (paths.raw_dir, paths.normalized_dir, paths.scored_dir):
            directory.mkdir(parents=True, exist_ok=True)

    def run_many(self, repos: list[RepoSpec], *, force: bool = False) -> list[dict[str, Any]]:
        records = [self.run_one(repo, force=force) for repo in repos]
        self._write_run_status(records)
        return records

    def run_one(self, repo: RepoSpec, *, force: bool = False) -> dict[str, Any]:
        normalized_path = self.paths.normalized_dir / f"{repo.name}.findings.json"
        raw_repo_dir = self.paths.raw_dir / repo.name
        if normalized_path.exists() and not force:
            return {
                "repo": repo.name,
                "status": "SKIPPED",
                "reason": "normalized findings already exist",
                "normalized": str(normalized_path),
            }

        checkout = self.repo_manager.prepare(repo)
        if checkout.status != "READY":
            record = {"repo": repo.name, "status": "ERROR", "stage": "checkout", "checkout": checkout.to_dict()}
            self._write_repo_status(repo.name, record)
            return record

        raw_repo_dir.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        scan = self._run_pipeline_subprocess(checkout.path, raw_repo_dir, repo.timeout_seconds)
        duration = round(time.monotonic() - started, 3)
        if scan["status"] != "COMPLETED":
            record = {
                "repo": repo.name,
                "status": "ERROR",
                "stage": "scan",
                "duration_seconds": duration,
                "checkout": checkout.to_dict(),
                "error": scan["error"],
            }
            self._write_repo_status(repo.name, record)
            return record

        try:
            scan_output = load_scan_output(raw_repo_dir)
        except Exception as exc:  # pylint: disable=broad-except
            record = {
                "repo": repo.name,
                "status": "ERROR",
                "stage": "normalize",
                "duration_seconds": duration,
                "checkout": checkout.to_dict(),
                "error": f"failed to load scanner reports: {str(exc)[:500]}",
            }
            self._write_repo_status(repo.name, record)
            return record
        findings = [finding.to_dict() for finding in normalize_scan_output(repo.name, scan_output)]
        normalized_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        baselines = [status.to_dict() for status in run_baseline_stubs(repo, checkout.path)]
        record = {
            "repo": repo.name,
            "status": "COMPLETED",
            "duration_seconds": duration,
            "checkout": checkout.to_dict(),
            "finding_count": len(findings),
            "normalized": str(normalized_path),
            "baselines": baselines,
        }
        self._write_repo_status(repo.name, record)
        return record

    def _run_pipeline_subprocess(self, target: Path, reports_dir: Path, timeout: int) -> dict[str, str | int]:
        workspace = Path.cwd()
        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(workspace) if not existing_pythonpath else f"{workspace}{os.pathsep}{existing_pythonpath}"
        code = (
            "from pathlib import Path; "
            "from security_system.application.pipeline import run_pipeline; "
            "decision = run_pipeline(Path(r'" + str(target) + "'), Path(r'" + str(reports_dir) + "')); "
            "raise SystemExit(decision.exit_code())"
        )
        try:
            result = subprocess.run(
                [sys.executable, "-c", code],
                cwd=target,
                env=env,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "ERROR", "error": f"scan timed out after {timeout}s"}
        if result.returncode not in (0, 1):
            return {"status": "ERROR", "error": (result.stderr or result.stdout).strip()[:1000]}
        log_path = reports_dir / "security-pipeline.log"
        log_path.write_text(
            f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}",
            encoding="utf-8"
        )
        return {"status": "COMPLETED", "error": ""}

    def _write_repo_status(self, repo_name: str, record: dict[str, Any]) -> None:
        status_dir = self.paths.results_dir / "runs"
        status_dir.mkdir(parents=True, exist_ok=True)
        (status_dir / f"{repo_name}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")

    def _write_run_status(self, records: list[dict[str, Any]]) -> None:
        self.paths.results_dir.mkdir(parents=True, exist_ok=True)
        (self.paths.results_dir / "run-status.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
