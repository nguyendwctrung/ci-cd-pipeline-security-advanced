from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from security_system.application.use_cases.make_decision import make_decision
from security_system.domain.models import AnalysisResult, SecurityIssue, Severity
from security_system.domain.parsers import ToolSummary


def _analysis(
    *,
    recommended_decision: str,
    is_malicious: bool = False,
    errors: list[str] | None = None,
) -> AnalysisResult:
    return AnalysisResult(
        timestamp="2026-06-08T00:00:00",
        recommended_decision=recommended_decision,
        risk_level="HIGH" if recommended_decision == "FAIL" else "LOW",
        is_malicious=is_malicious,
        detected_patterns=["test-pattern"] if recommended_decision == "FAIL" else [],
        recommendations=["test recommendation"],
        reasoning="test analysis",
        scan_issues_count=0,
        errors=errors or [],
    )


def _summary(issues: list[SecurityIssue]) -> ToolSummary:
    by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for issue in issues:
        by_severity[issue.severity.value] += 1
    return ToolSummary(
        tool="test",
        total_findings=len(issues),
        by_severity=by_severity,
        issues=issues,
    )


class MakeDecisionTest(unittest.TestCase):
    def test_llm_unavailable_keeps_clean_policy_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = make_decision(
                _analysis(
                    recommended_decision="WARN",
                    errors=["GOOGLE_API_KEY is not set"],
                ),
                {"test": _summary([])},
                Path(tmp),
            )

        self.assertEqual(report.decision, "PASS")
        self.assertEqual(report.metadata["llm_decision"], "UNAVAILABLE")
        self.assertEqual(report.metadata["final_decision_source"], "policy")

    def test_llm_unavailable_preserves_policy_fail(self) -> None:
        issue = SecurityIssue(
            tool="trivy",
            severity=Severity.CRITICAL,
            type="CVE-0000-0000",
            message="critical vulnerability",
        )
        with tempfile.TemporaryDirectory() as tmp:
            report = make_decision(
                _analysis(recommended_decision="WARN", errors=["LLM unavailable"]),
                {"test": _summary([issue])},
                Path(tmp),
            )

        self.assertEqual(report.decision, "FAIL")
        self.assertEqual(report.metadata["llm_decision"], "UNAVAILABLE")

    def test_policy_fail_wins_over_llm_pass(self) -> None:
        issue = SecurityIssue(
            tool="gitleaks",
            severity=Severity.HIGH,
            type="generic-api-key",
            message="secret detected",
        )
        with tempfile.TemporaryDirectory() as tmp:
            report = make_decision(
                _analysis(recommended_decision="PASS"),
                {"test": _summary([issue])},
                Path(tmp),
            )

        self.assertEqual(report.decision, "FAIL")
        self.assertEqual(report.metadata["final_decision_source"], "policy")

    def test_llm_fail_wins_over_policy_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = make_decision(
                _analysis(recommended_decision="FAIL", is_malicious=True),
                {"test": _summary([])},
                Path(tmp),
            )

        self.assertEqual(report.decision, "FAIL")
        self.assertEqual(report.metadata["final_decision_source"], "llm")

    def test_high_policy_fail_wins_over_llm_pass(self) -> None:
        issue = SecurityIssue(
            tool="semgrep",
            severity=Severity.HIGH,
            type="test-rule",
            message="high severity finding",
        )
        with tempfile.TemporaryDirectory() as tmp:
            report = make_decision(
                _analysis(recommended_decision="PASS"),
                {"test": _summary([issue])},
                Path(tmp),
            )

        self.assertEqual(report.decision, "FAIL")
        self.assertEqual(report.metadata["final_decision_source"], "policy")

    def test_llm_unavailable_preserves_high_policy_fail(self) -> None:
        issue = SecurityIssue(
            tool="trivy",
            severity=Severity.HIGH,
            type="CVE-0000-0001",
            message="high vulnerability",
        )
        with tempfile.TemporaryDirectory() as tmp:
            report = make_decision(
                _analysis(recommended_decision="WARN", errors=["LLM unavailable"]),
                {"test": _summary([issue])},
                Path(tmp),
            )

        self.assertEqual(report.decision, "FAIL")
        self.assertEqual(report.metadata["llm_decision"], "UNAVAILABLE")

    def test_llm_unavailable_preserves_medium_policy_warn(self) -> None:
        issue = SecurityIssue(
            tool="semgrep",
            severity=Severity.MEDIUM,
            type="test-rule",
            message="medium finding",
        )
        with tempfile.TemporaryDirectory() as tmp:
            report = make_decision(
                _analysis(recommended_decision="WARN", errors=["LLM unavailable"]),
                {"test": _summary([issue])},
                Path(tmp),
            )

        self.assertEqual(report.decision, "WARN")
        self.assertEqual(report.metadata["final_decision_source"], "policy")

    def test_llm_warn_wins_over_policy_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = make_decision(
                _analysis(recommended_decision="WARN"),
                {"test": _summary([])},
                Path(tmp),
            )

        self.assertEqual(report.decision, "WARN")
        self.assertEqual(report.metadata["final_decision_source"], "llm")


if __name__ == "__main__":
    unittest.main()
