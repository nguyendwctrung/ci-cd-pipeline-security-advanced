"""Aggregate reports produced by parallel CI scanner jobs."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from security_system.application.monitoring import PipelineMonitor
from security_system.application.use_cases.analyze import analyze
from security_system.application.use_cases.make_decision import _build_summary_dict, make_decision
from security_system.application.use_cases.run_scan import REPORT_PATHS, load_scan_output
from security_system.domain.models import AnalysisResult, DecisionReport
from security_system.domain.services import GitService
from security_system.infrastructure.storage import ArtifactStore, ensure_dir


logger = logging.getLogger(__name__)


def run_aggregation(
    scanner_dir: Path,
    reports_dir: Path,
    *,
    api_key: Optional[str] = None,
) -> DecisionReport:
    """Build the final decision and reports from parallel scanner artifacts."""
    ensure_dir(reports_dir)
    monitor = PipelineMonitor()
    store = ArtifactStore(reports_dir)

    try:
        with monitor.stage("git_context"):
            git_context = GitService().get_context()
            monitor.record_git(git_context)

        failures = _collect_scanner_artifacts(scanner_dir, reports_dir, monitor)
        scan_output = load_scan_output(reports_dir, monitor=monitor)
        if failures:
            error = RuntimeError("; ".join(failures))
            decision = _save_aggregation_failure(
                store,
                scan_output.summaries,
                error,
            )
            monitor.record_decision(decision)
            monitor.record_error("SCANNER_FAILURE", error)
            return decision

        with monitor.stage("gemini_analysis"):
            analysis = analyze(scan_output, git_context, api_key=api_key)
            monitor.record_analysis(analysis)
        with monitor.stage("policy_decision"):
            decision = make_decision(analysis, scan_output.summaries, reports_dir)
            monitor.record_decision(decision)
        with monitor.stage("artifact_generation"):
            store.save_analysis(analysis.to_dict())
            store.save_decision(decision.to_dict())
            store.save_summary(_build_summary_dict(scan_output.summaries))
        return decision
    except Exception as exc:
        logger.exception("Aggregation pipeline failed")
        monitor.record_error("PIPELINE_EXCEPTION", exc)
        raise
    finally:
        store.save_monitor(monitor.to_dict())


def _collect_scanner_artifacts(
    scanner_dir: Path,
    reports_dir: Path,
    monitor: PipelineMonitor,
) -> list[str]:
    failures: list[str] = []
    for tool, report_name in REPORT_PATHS.items():
        manifest_path = scanner_dir / f"{tool}-manifest.json"
        report_path = scanner_dir / report_name
        manifest = _load_manifest(manifest_path)
        if manifest is None:
            failures.append(f"{tool}: manifest missing or malformed")
            monitor.record_stage(f"{tool}_scan", "ERROR", 0, failures[-1])
            monitor.record_scanner(tool, "ERROR", failures[-1])
            _write_empty_report(tool, reports_dir / report_name)
            continue
        status = str(manifest.get("status", "ERROR"))
        duration = float(manifest.get("duration_seconds", 0) or 0)
        error = str(manifest.get("error") or "") or None
        monitor.record_stage(f"{tool}_scan", status, duration, error)
        monitor.record_scanner(tool, "HEALTHY" if status == "COMPLETED" else "ERROR", error)
        if status != "COMPLETED":
            failures.append(f"{tool}: {error or 'scanner failed'}")
            _write_empty_report(tool, reports_dir / report_name)
            continue
        if not report_path.exists():
            failures.append(f"{tool}: report missing")
            monitor.record_stage(f"{tool}_scan", "ERROR", duration, failures[-1])
            monitor.record_scanner(tool, "ERROR", failures[-1])
            _write_empty_report(tool, reports_dir / report_name)
            continue
        try:
            with report_path.open("r", encoding="utf-8") as handle:
                json.load(handle)
            (reports_dir / report_name).write_bytes(report_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{tool}: invalid report ({str(exc)[:200]})")
            monitor.record_stage(f"{tool}_scan", "ERROR", duration, failures[-1])
            monitor.record_scanner(tool, "ERROR", failures[-1])
            _write_empty_report(tool, reports_dir / report_name)
    return failures


def _load_manifest(path: Path) -> Optional[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _write_empty_report(tool: str, path: Path) -> None:
    empty: Any = [] if tool == "gitleaks" else {
        "semgrep": {"results": []},
        "trivy": {"Results": []},
    }[tool]
    path.write_text(json.dumps(empty), encoding="utf-8")


def _save_aggregation_failure(
    store: ArtifactStore,
    summaries: dict[str, Any],
    error: RuntimeError,
) -> DecisionReport:
    timestamp = datetime.now().isoformat()
    analysis = AnalysisResult.fallback(timestamp, str(error))
    report = DecisionReport(
        timestamp=timestamp,
        decision="FAIL",
        reason=f"Scanner execution failed: {error}",
        is_malicious=False,
        recommendations=["Fix scanner installation or execution before merging."],
        metadata={
            "policy_decision": "FAIL",
            "llm_decision": "UNAVAILABLE",
            "llm_available": False,
            "scanner_failures": [str(error)],
            "final_decision_source": "scanner_failure",
        },
    )
    summary = _build_summary_dict(summaries)
    summary["scanner_failures"] = [str(error)]
    store.save_analysis(analysis.to_dict())
    store.save_decision(report.to_dict())
    store.save_summary(summary)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner-dir", type=Path, required=True)
    parser.add_argument("--reports-dir", type=Path, required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    decision = run_aggregation(args.scanner_dir, args.reports_dir)
    sys.exit(decision.exit_code())


if __name__ == "__main__":
    main()
