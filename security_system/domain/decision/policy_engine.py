"""
Policy-based decision engine for scan issues.

Contains pure business rules that convert normalized SecurityIssue entries
into a DecisionReport.
"""

from __future__ import annotations

from datetime import datetime

from security_system.domain.models import DecisionReport, SecurityIssue


class PolicyEngine:
    """Evaluates security issues using simple severity-based policy rules."""

    def evaluate(self, issues: list[SecurityIssue]) -> DecisionReport:
        """
        Apply policy rules to a list of security issues.

        Rules (priority order):
        - Any Gitleaks secret -> FAIL
        - Any CRITICAL issue -> FAIL
        - Any HIGH issue -> FAIL
        - Else any MEDIUM issue -> WARN
        - Else -> PASS
        """
        total_issue_count = len(issues)
        severity_counts = {
            severity: sum(
                1 for issue in issues if self._severity_of(issue) == severity
            )
            for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        }
        has_secret = any(issue.tool.lower() == "gitleaks" for issue in issues)
        has_critical = severity_counts["CRITICAL"] > 0
        has_high = severity_counts["HIGH"] > 0
        has_medium = severity_counts["MEDIUM"] > 0

        if has_secret:
            decision = "FAIL"
            reason_code = "GITLEAKS_SECRET"
            summary = "Secret detected by Gitleaks; policy evaluation result is FAIL"
        elif has_critical:
            decision = "FAIL"
            reason_code = "CRITICAL_FINDING"
            summary = (
                "Critical severity issue detected; policy evaluation result is FAIL"
            )
        elif has_high:
            decision = "FAIL"
            reason_code = "HIGH_FINDING"
            summary = "High severity issue detected; policy evaluation result is FAIL"
        elif has_medium:
            decision = "WARN"
            reason_code = "MEDIUM_FINDING"
            summary = "Medium severity issue detected; policy evaluation result is WARN"
        else:
            decision = "PASS"
            reason_code = "NO_BLOCKING_FINDINGS"
            summary = "No MEDIUM, HIGH, or CRITICAL issues detected; policy evaluation result is PASS"

        return DecisionReport(
            timestamp=datetime.now().isoformat(),
            decision=decision,
            reason=summary,
            is_malicious=False,
            detected_patterns=[],
            recommendations=[],
            metadata={
                "status": decision,
                "summary": summary,
                "reason_code": reason_code,
                "severity_counts": severity_counts,
                "total_issue_count": total_issue_count,
                "gitleaks_secret_count": sum(
                    1 for issue in issues if issue.tool.lower() == "gitleaks"
                ),
            },
        )

    @staticmethod
    def _severity_of(issue: SecurityIssue) -> str:
        """Returns a normalized severity string for a SecurityIssue."""
        severity = issue.severity
        if hasattr(severity, "value"):
            return str(severity.value).upper()
        return str(severity).upper()
