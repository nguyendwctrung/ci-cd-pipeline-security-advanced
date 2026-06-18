from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_system.application.monitoring import PipelineMonitor
from security_system.application.monitor_reporting import render_markdown
from security_system.application.pipeline import (
    _save_scanner_failure_decision,
    run_pipeline,
)
from security_system.domain.models import DecisionReport, GitContext


class PipelineTest(unittest.TestCase):
    def test_scanner_failure_is_blocking_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports_dir = Path(tmp)
            report = _save_scanner_failure_decision(
                reports_dir,
                RuntimeError("Trivy scanner failed or is not installed."),
            )

            saved = json.loads((reports_dir / "decision_report.json").read_text())

        self.assertEqual(report.decision, "FAIL")
        self.assertEqual(saved["decision"], "FAIL")
        self.assertEqual(saved["metadata"]["final_decision_source"], "scanner_failure")
        self.assertNotIn("risk_score", saved)
        self.assertNotIn("fail_threshold", saved)
        self.assertNotIn("warn_threshold", saved)

    def test_monitor_distinguishes_blocked_from_error(self) -> None:
        monitor = PipelineMonitor()
        monitor.record_decision(DecisionReport(
            timestamp="2026-06-12T00:00:00Z",
            decision="FAIL",
            reason="Critical finding",
            is_malicious=False,
            metadata={"policy_decision": "FAIL"},
        ))

        self.assertEqual(monitor.to_dict()["pipeline_status"], "BLOCKED")

        monitor.record_error("SCANNER_FAILURE", "Trivy unavailable")
        report = monitor.to_dict()
        self.assertEqual(report["pipeline_status"], "ERROR")
        self.assertEqual(report["error"]["category"], "SCANNER_FAILURE")

    def test_fail_decision_blocks_shell_and_monitoring(self) -> None:
        decision = DecisionReport(
            timestamp="2026-06-15T00:00:00Z",
            decision="FAIL",
            reason="High severity finding",
            is_malicious=False,
            metadata={"policy_decision": "FAIL"},
        )
        monitor = PipelineMonitor()
        monitor.record_decision(decision)

        self.assertEqual(decision.exit_code(), 1)
        self.assertEqual(monitor.to_dict()["pipeline_status"], "BLOCKED")

    def test_unexpected_failure_still_writes_monitor_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports_dir = Path(tmp)
            with patch(
                "security_system.application.pipeline.GitService.get_context",
                return_value=GitContext.empty(),
            ), patch(
                "security_system.application.pipeline.run_scan",
                side_effect=ValueError("unexpected test failure"),
            ):
                with self.assertRaises(ValueError):
                    run_pipeline(reports_dir=reports_dir)

            monitor = json.loads((reports_dir / "monitor_report.json").read_text())

        self.assertEqual(monitor["pipeline_status"], "ERROR")
        self.assertEqual(monitor["error"]["category"], "PIPELINE_EXCEPTION")
        self.assertNotIn("source", monitor)

    def test_monitor_summary_contains_categorical_results(self) -> None:
        monitor = PipelineMonitor()
        monitor.record_decision(DecisionReport(
            timestamp="2026-06-12T00:00:00Z",
            decision="WARN",
            reason="High severity finding",
            is_malicious=False,
            metadata={"policy_decision": "WARN", "llm_available": False},
        ))
        summary = render_markdown(monitor.to_dict())

        self.assertIn("Pipeline status | **COMPLETED**", summary)
        self.assertIn("Final decision | **WARN**", summary)
        self.assertNotIn("Risk Score", summary)


if __name__ == "__main__":
    unittest.main()
