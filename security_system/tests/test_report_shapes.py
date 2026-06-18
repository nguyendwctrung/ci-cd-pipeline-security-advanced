from __future__ import annotations

import unittest

from security_system.application.use_cases.make_decision import _build_summary_dict
from security_system.domain.models import SecurityIssue, Severity
from security_system.domain.parsers import ToolSummary


class ReportShapeTest(unittest.TestCase):
    def test_issue_and_summaries_do_not_emit_numeric_scores(self) -> None:
        issue = SecurityIssue(
            tool="semgrep",
            severity=Severity.HIGH,
            type="test-rule",
            message="high severity finding",
        )
        summary = ToolSummary(
            tool="semgrep",
            total_findings=1,
            by_severity={"LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0},
            issues=[issue],
        )
        aggregate = _build_summary_dict({"semgrep": summary})

        self.assertNotIn("score", issue.to_dict())
        self.assertNotIn("average_score", summary.to_dict())
        self.assertNotIn("overall_score", aggregate)


if __name__ == "__main__":
    unittest.main()
