"""
Security pipeline orchestrator.

Wires together all layers in sequence:
  1. run_scan    — CLI scanners + domain parsers
  2. analyze     — LLM analysis (injected GeminiProvider)
  3. make_decision — domain risk evaluation
  4. Save artifacts via infrastructure/storage

Contains NO business logic — only calls use cases and saves results.

Entry point:
	python -m security_system.application.pipeline
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from security_system.application.monitoring import PipelineMonitor
from security_system.application.use_cases.run_scan import run_scan
from security_system.application.use_cases.analyze import analyze
from security_system.application.use_cases.make_decision import make_decision, _build_summary_dict
from security_system.config.constants import REPORTS_DIR as DEFAULT_REPORTS_DIR
from security_system.domain.models import AnalysisResult, DecisionReport
from security_system.domain.services import GitService
from security_system.infrastructure.storage import ArtifactStore, ensure_dir

logger = logging.getLogger(__name__)


def run_pipeline(
    target: Path = Path("."),
    reports_dir: Path = DEFAULT_REPORTS_DIR,
    *,
    api_key: Optional[str] = None,
) -> DecisionReport:
	"""
	Execute the full CI/CD security pipeline.

	Args:
		target:      Repository or directory to scan (default: current dir).
		reports_dir: Where to write all reports (default: reports/artifacts/).
		api_key:     Explicit Gemini API key; falls back to GOOGLE_API_KEY env var.

	Returns:
		DecisionReport with PASS / WARN / FAIL decision.

	Raises:
		RuntimeError: If any scanner binary is missing.
	"""
	ensure_dir(reports_dir)
	monitor = PipelineMonitor()
	store = ArtifactStore(reports_dir)

	logger.info("=" * 60)
	logger.info("CI/CD Security Pipeline started (target: %s)", target)
	logger.info("=" * 60)

	try:
		# --- Step 1: Git context ----------------------------------------------
		logger.info("Step 1/4 — Collecting git context")
		with monitor.stage("git_context"):
			git_ctx = GitService().get_context()
			monitor.record_git(git_ctx)
		logger.info("Commit: %s by %s", git_ctx.commit_hash, git_ctx.author)

		# --- Step 2: Scan -----------------------------------------------------
		logger.info("Step 2/4 — Running security scanners")
		try:
			scan_output = run_scan(target, reports_dir, monitor=monitor)
		except RuntimeError as exc:
			logger.error("Scanner execution failed: %s", exc)
			decision_report = _save_scanner_failure_decision(reports_dir, exc)
			monitor.record_decision(decision_report)
			monitor.record_error("SCANNER_FAILURE", exc)
			return decision_report

		# --- Step 3: Analyze --------------------------------------------------
		logger.info("Step 3/4 — Running LLM analysis")
		with monitor.stage("gemini_analysis"):
			analysis = analyze(scan_output, git_ctx, api_key=api_key)
			monitor.record_analysis(analysis)

		# --- Step 4: Decide ---------------------------------------------------
		logger.info("Step 4/4 — Making security decision")
		with monitor.stage("policy_decision"):
			decision_report = make_decision(analysis, scan_output.summaries, reports_dir)
			monitor.record_decision(decision_report)

		# --- Save artifacts ---------------------------------------------------
		with monitor.stage("artifact_generation"):
			store.save_analysis(analysis.to_dict())
			store.save_decision(decision_report.to_dict())
			store.save_summary(_build_summary_dict(scan_output.summaries))

		logger.info("=" * 60)
		logger.info("Pipeline complete — decision: %s", decision_report.decision)
		logger.info("=" * 60)
		return decision_report
	except Exception as exc:
		logger.exception("Unexpected pipeline failure")
		monitor.record_error("PIPELINE_EXCEPTION", exc)
		raise
	finally:
		store.save_monitor(monitor.to_dict())


def _save_scanner_failure_decision(
	reports_dir: Path,
	error: RuntimeError,
) -> DecisionReport:
	"""Persist a blocking decision when scanner execution cannot complete."""
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
	store = ArtifactStore(reports_dir)
	store.save_analysis(analysis.to_dict())
	store.save_decision(report.to_dict())
	store.save_summary({
		"timestamp": timestamp,
		"total_findings": 0,
		"by_tool": {},
		"by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
		"scanner_failures": [str(error)],
	})
	return report


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
	)
	decision = run_pipeline()
	sys.exit(decision.exit_code())
