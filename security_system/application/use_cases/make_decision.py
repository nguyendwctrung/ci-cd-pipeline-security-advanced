"""
make_decision use case — orchestrates risk evaluation and report creation.

Dependency flow:
  AnalysisResult + summaries → domain/decision/DecisionEngine → DecisionReport

No business logic here. Only assembles inputs and calls the domain engine.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from security_system.domain.decision import DecisionEngine
from security_system.domain.decision.policy_engine import PolicyEngine
from security_system.domain.models import AnalysisResult, DecisionReport, SecurityIssue
from security_system.domain.parsers import ToolSummary

logger = logging.getLogger(__name__)


def make_decision(
	analysis: AnalysisResult | list[SecurityIssue],
	summaries: Dict[str, ToolSummary] | None = None,
	reports_dir: Path | None = None,
) -> DecisionReport:
	"""
	Produce a final DecisionReport using either:
	- PolicyEngine for a list of SecurityIssue objects, or
	- DecisionEngine for the legacy AnalysisResult + summaries flow.

	Args:
		analysis:    Either AnalysisResult or list[SecurityIssue].
		summaries:   Per-tool ToolSummary objects from the run_scan use case
		             (legacy AnalysisResult path only).
		reports_dir: Directory where the decision report will be persisted
		             (legacy AnalysisResult path only).

	Returns:
		DecisionReport with PASS / WARN / FAIL decision.
	"""
	if isinstance(analysis, list) and (
		not analysis or all(isinstance(issue, SecurityIssue) for issue in analysis)
	):
		report = PolicyEngine().evaluate(analysis)
		logger.info("Decision: %s (policy path)", report.decision)
		return report

	if summaries is None or reports_dir is None:
		raise ValueError(
			"summaries and reports_dir are required when analysis is AnalysisResult"
		)

	if not isinstance(analysis, AnalysisResult):
		raise ValueError(
			"analysis must be AnalysisResult for the legacy DecisionEngine path"
		)

	summary_dict = _build_summary_dict(summaries)
	issues = [
		issue
		for summary in summaries.values()
		for issue in summary.issues
	]

	policy_report = PolicyEngine().evaluate(issues)
	engine = DecisionEngine(reports_dir=reports_dir)
	llm_report = engine.decide(analysis, summary_dict)
	report = _merge_decisions(policy_report, llm_report, analysis)

	logger.info(
		"Decision: %s (policy=%s, llm=%s)",
		report.decision,
		policy_report.decision,
		llm_report.decision,
	)
	return report


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _build_summary_dict(summaries: Dict[str, ToolSummary]) -> Dict[str, Any]:
	"""
	Aggregates ToolSummary objects into the summary dict expected by
	DecisionEngine.decide() as optional metadata.
	"""
	by_severity: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
	for ts in summaries.values():
		for level, count in ts.by_severity.items():
			by_severity[level] = by_severity.get(level, 0) + count

	total = sum(ts.total_findings for ts in summaries.values())
	return {
		"timestamp": datetime.now().isoformat(),
		"total_findings": total,
		"by_tool": {name: ts.total_findings for name, ts in summaries.items()},
		"by_severity": by_severity,
		"tools": [ts.to_dict() for ts in summaries.values()],
	}


def _merge_decisions(
	policy_report: DecisionReport,
	llm_report: DecisionReport,
	analysis: AnalysisResult,
) -> DecisionReport:
	"""
	Combine scanner policy and LLM analysis into the final gate decision.

	Scanner policy is always authoritative. LLM analysis can make an available
	decision stricter, but an unavailable/failed LLM cannot weaken or raise the
	scanner policy result.
	"""
	llm_available = not analysis.errors
	if llm_available:
		final = _stricter_report(policy_report, llm_report)
	else:
		final = policy_report

	metadata = dict(final.metadata)
	metadata.update({
		"policy_decision": policy_report.decision,
		"llm_decision": llm_report.decision if llm_available else "UNAVAILABLE",
		"llm_available": llm_available,
		"llm_errors": list(analysis.errors),
		"final_decision_source": _decision_source(
			final,
			policy_report,
			llm_report,
			llm_available,
		),
		"policy_metadata": policy_report.metadata,
		"llm_metadata": llm_report.metadata,
	})

	return DecisionReport(
		timestamp=final.timestamp,
		decision=final.decision,
		reason=_combined_reason(policy_report, llm_report, llm_available, final),
		is_malicious=llm_report.is_malicious if llm_available else False,
		detected_patterns=list(llm_report.detected_patterns) if llm_available else [],
		recommendations=list(llm_report.recommendations),
		metadata=metadata,
	)


def _stricter_report(left: DecisionReport, right: DecisionReport) -> DecisionReport:
	"""Return the report with the stricter decision."""
	order = {"PASS": 0, "WARN": 1, "FAIL": 2}
	if order[right.decision] > order[left.decision]:
		return right
	return left


def _decision_source(
	final: DecisionReport,
	policy_report: DecisionReport,
	llm_report: DecisionReport,
	llm_available: bool,
) -> str:
	"""Describe which input determined the final decision."""
	if not llm_available:
		return "policy"
	if final.decision == policy_report.decision == llm_report.decision:
		return "policy_and_llm"
	if final.decision == policy_report.decision:
		return "policy"
	return "llm"


def _combined_reason(
	policy_report: DecisionReport,
	llm_report: DecisionReport,
	llm_available: bool,
	final: DecisionReport,
) -> str:
	"""Build a concise final reason that records both decision sources."""
	if not llm_available:
		return f"{policy_report.reason}; LLM analysis unavailable"
	if final.decision == policy_report.decision == llm_report.decision:
		return f"{policy_report.reason}; LLM also returned {llm_report.decision}"
	if final.decision == policy_report.decision:
		return f"{policy_report.reason}; LLM returned {llm_report.decision}"
	return f"{llm_report.reason}; scanner policy returned {policy_report.decision}"
