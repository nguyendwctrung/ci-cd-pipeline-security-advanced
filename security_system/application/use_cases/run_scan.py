"""
run_scan use case — orchestrates scanner execution and parsing.

Dependency flow:
  infrastructure/scanners → (raw JSON files) → domain/parsers → ScanOutput

No business logic here. Only wires infra CLI runners to domain parsers.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from security_system.application.monitoring import PipelineMonitor

from security_system.domain.models import SecurityIssue
from security_system.domain.parsers import (
	GitleaksParser,
	SemgrepParser,
	TrivyParser,
	ToolSummary,
)
from security_system.infrastructure.scanners import run_gitleaks, run_semgrep, run_trivy
from security_system.infrastructure.storage.artifact_store import (
	GITLEAKS_REPORT,
	SEMGREP_REPORT,
	TRIVY_REPORT,
)

logger = logging.getLogger(__name__)

REPORT_PATHS = {
	"gitleaks": GITLEAKS_REPORT,
	"semgrep": SEMGREP_REPORT,
	"trivy": TRIVY_REPORT,
}


@dataclass
class ScanOutput:
	"""
	Result of the scan step.

	Attributes:
		summaries:  Per-tool ToolSummary objects (normalized findings + stats).
		raw_data:   Raw JSON findings per tool — used to build LLM prompt.
		all_issues: Flat list of all normalized SecurityIssue objects.
	"""

	summaries: Dict[str, ToolSummary] = field(default_factory=dict)
	raw_data: Dict[str, List[Any]] = field(default_factory=dict)
	all_issues: List[SecurityIssue] = field(default_factory=list)


def run_scan(
	target: Path,
	reports_dir: Path,
	monitor: Optional[PipelineMonitor] = None,
) -> ScanOutput:
	"""
	Run all three security scanners against *target* and return normalized output.

	Steps:
	  1. Execute Gitleaks / Semgrep / Trivy CLI via infrastructure adapters,
		 writing JSON reports to *reports_dir*.
	  2. Parse each report with the corresponding domain parser.
	  3. Build raw_data dict (for LLM prompt consumption).
	  4. Return ScanOutput.

	Args:
		target:      Path to the repository or directory to scan.
		reports_dir: Directory where scanner JSON reports will be written.

	Returns:
		ScanOutput with summaries, raw findings, and flattened issue list.

	Raises:
		RuntimeError: If a scanner binary is not found (returns None).
	"""
	reports_dir.mkdir(parents=True, exist_ok=True)

	gl_path = reports_dir / GITLEAKS_REPORT
	sg_path = reports_dir / SEMGREP_REPORT
	tv_path = reports_dir / TRIVY_REPORT

	# --- Step 1: Run scanners (CLI via infra) --------------------------------
	logger.info("Running Gitleaks on %s", target)
	if monitor:
		monitor.start_stage("gitleaks_scan")
	gl_raw = run_gitleaks(target, output_path=gl_path)
	if gl_raw is None:
		if monitor:
			monitor.finish_stage("gitleaks_scan", "ERROR", "Scanner execution failed")
			monitor.record_scanner("gitleaks", "ERROR", "Scanner execution failed")
		raise RuntimeError("Gitleaks scanner failed or is not installed.")
	if monitor:
		monitor.finish_stage("gitleaks_scan", "COMPLETED")
		monitor.record_scanner("gitleaks", "HEALTHY")

	logger.info("Running Semgrep on %s", target)
	if monitor:
		monitor.start_stage("semgrep_scan")
	sg_raw = run_semgrep(target, output_path=sg_path)
	if sg_raw is None:
		if monitor:
			monitor.finish_stage("semgrep_scan", "ERROR", "Scanner execution failed")
			monitor.record_scanner("semgrep", "ERROR", "Scanner execution failed")
		raise RuntimeError("Semgrep scanner failed or is not installed.")
	if monitor:
		monitor.finish_stage("semgrep_scan", "COMPLETED")
		monitor.record_scanner("semgrep", "HEALTHY")

	logger.info("Running Trivy on %s", target)
	if monitor:
		monitor.start_stage("trivy_scan")
	tv_raw = run_trivy(target, output_path=tv_path)
	if tv_raw is None:
		if monitor:
			monitor.finish_stage("trivy_scan", "ERROR", "Scanner execution failed")
			monitor.record_scanner("trivy", "ERROR", "Scanner execution failed")
		raise RuntimeError("Trivy scanner failed or is not installed.")
	if monitor:
		monitor.finish_stage("trivy_scan", "COMPLETED")
		monitor.record_scanner("trivy", "HEALTHY")

	# --- Step 2: Parse normalized reports ------------------------------------
	scan_output = load_scan_output(reports_dir, monitor=monitor)

	logger.info(
		"Scan complete — %d total findings (%d gitleaks, %d semgrep, %d trivy)",
		len(scan_output.all_issues),
		len(scan_output.summaries["gitleaks"].issues),
		len(scan_output.summaries["semgrep"].issues),
		len(scan_output.summaries["trivy"].issues),
	)

	return scan_output


def load_scan_output(
	reports_dir: Path,
	*,
	monitor: Optional[PipelineMonitor] = None,
) -> ScanOutput:
	"""Load and normalize scanner reports produced locally or by CI jobs."""
	logger.info("Parsing scan reports")
	if monitor:
		monitor.start_stage("report_parsing")

	parsers = {
		"gitleaks": GitleaksParser(),
		"semgrep": SemgrepParser(),
		"trivy": TrivyParser(),
	}
	summaries = {
		tool: parser.parse_file(reports_dir / REPORT_PATHS[tool])
		for tool, parser in parsers.items()
	}
	raw_data = {
		tool: _load_raw_findings(tool, reports_dir / REPORT_PATHS[tool])
		for tool in REPORT_PATHS
	}
	all_issues = [
		issue
		for summary in summaries.values()
		for issue in summary.issues
	]

	if monitor:
		monitor.finish_stage("report_parsing", "COMPLETED")
		monitor.record_findings(summaries)

	return ScanOutput(
		summaries=summaries,
		raw_data=raw_data,
		all_issues=all_issues,
	)


def _load_raw_findings(tool: str, path: Path) -> List[Any]:
	"""Return the scanner finding list from its native JSON envelope."""
	with path.open("r", encoding="utf-8") as handle:
		data = json.load(handle)
	if tool == "gitleaks":
		return data if isinstance(data, list) else list(data.get("Leaks", []))
	if tool == "semgrep":
		return list(data.get("results", [])) if isinstance(data, dict) else list(data)
	if tool == "trivy":
		return list(data.get("Results", [])) if isinstance(data, dict) else list(data)
	raise ValueError(f"Unsupported scanner: {tool}")
