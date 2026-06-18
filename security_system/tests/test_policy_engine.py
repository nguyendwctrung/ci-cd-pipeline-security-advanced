from __future__ import annotations

import unittest

from security_system.domain.decision.policy_engine import PolicyEngine
from security_system.domain.models import SecurityIssue, Severity


class PolicyEngineTest(unittest.TestCase):
    def test_no_findings_passes(self) -> None:
        report = PolicyEngine().evaluate([])

        self.assertEqual(report.decision, "PASS")

    def test_high_finding_fails(self) -> None:
        report = PolicyEngine().evaluate([
            SecurityIssue(
                tool="semgrep",
                severity=Severity.HIGH,
                type="test-rule",
                message="high severity finding",
            )
        ])

        self.assertEqual(report.decision, "FAIL")
        self.assertEqual(report.metadata["reason_code"], "HIGH_FINDING")
        self.assertEqual(report.metadata["severity_counts"]["HIGH"], 1)

    def test_medium_finding_warns(self) -> None:
        report = PolicyEngine().evaluate([
            SecurityIssue(
                tool="semgrep",
                severity=Severity.MEDIUM,
                type="test-rule",
                message="medium severity finding",
            )
        ])

        self.assertEqual(report.decision, "WARN")
        self.assertEqual(report.metadata["reason_code"], "MEDIUM_FINDING")

    def test_low_finding_passes(self) -> None:
        report = PolicyEngine().evaluate([
            SecurityIssue(
                tool="semgrep",
                severity=Severity.LOW,
                type="test-rule",
                message="low severity finding",
            )
        ])

        self.assertEqual(report.decision, "PASS")
        self.assertEqual(report.metadata["severity_counts"]["LOW"], 1)

    def test_critical_finding_fails(self) -> None:
        report = PolicyEngine().evaluate([
            SecurityIssue(
                tool="trivy",
                severity=Severity.CRITICAL,
                type="CVE-0000-0000",
                message="critical vulnerability",
            )
        ])

        self.assertEqual(report.decision, "FAIL")

    def test_gitleaks_finding_fails_even_when_high(self) -> None:
        report = PolicyEngine().evaluate([
            SecurityIssue(
                tool="gitleaks",
                severity=Severity.HIGH,
                type="generic-api-key",
                message="secret detected",
            )
        ])

        self.assertEqual(report.decision, "FAIL")


if __name__ == "__main__":
    unittest.main()
