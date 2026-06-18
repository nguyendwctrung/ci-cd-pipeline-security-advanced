from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_system.application.aggregate_pipeline import run_aggregation
from security_system.application.changed_files import ChangedFileScope, _parse_name_status
from security_system.application.scanner_job import run_scanner_job
from security_system.domain.models import AnalysisResult, GitContext
from security_system.infrastructure.scanners.gitleaks import run_gitleaks
from security_system.infrastructure.scanners.gitleaks import _normalize_report_paths as normalize_gitleaks_paths
from security_system.infrastructure.scanners.semgrep import run_semgrep
from security_system.infrastructure.scanners.semgrep import _normalize_report_paths as normalize_semgrep_paths
from security_system.infrastructure.scanners.trivy import run_trivy
from security_system.infrastructure.scanners.trivy import _normalize_report_paths as normalize_trivy_paths


def _manifest(directory: Path, tool: str, status: str = "COMPLETED", error=None) -> None:
    (directory / f"{tool}-manifest.json").write_text(json.dumps({
        "schema_version": "1.0",
        "tool": tool,
        "status": status,
        "duration_seconds": 1.25,
        "report": f"{tool}-report.json",
        "error": error,
    }), encoding="utf-8")


def _empty_reports(directory: Path) -> None:
    (directory / "gitleaks-report.json").write_text("[]", encoding="utf-8")
    (directory / "semgrep-report.json").write_text('{"results": []}', encoding="utf-8")
    (directory / "trivy-report.json").write_text('{"Results": []}', encoding="utf-8")


def _unavailable_analysis(*args, **kwargs) -> AnalysisResult:
    return AnalysisResult.fallback("2026-06-15T00:00:00", "LLM unavailable")


class ScannerJobTest(unittest.TestCase):
    def test_success_and_empty_findings_write_valid_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)

            def empty_scanner(target, output_path):
                return []

            with patch.dict(
                "security_system.application.scanner_job.SCANNERS",
                {"gitleaks": empty_scanner},
                clear=False,
            ):
                manifest = run_scanner_job("gitleaks", Path("."), output)

            self.assertEqual(manifest["status"], "COMPLETED")
            self.assertEqual(json.loads((output / "gitleaks-report.json").read_text()), [])

    def test_missing_binary_or_timeout_records_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            with patch.dict(
                "security_system.application.scanner_job.SCANNERS",
                {"trivy": lambda target, output_path: None},
                clear=False,
            ):
                manifest = run_scanner_job("trivy", Path("."), output)

            self.assertEqual(manifest["status"], "ERROR")
            self.assertIn("failed or is unavailable", manifest["error"])

    def test_install_failure_records_error_without_running_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = run_scanner_job(
                "semgrep",
                Path("."),
                Path(tmp),
                installation_status="failure",
            )

        self.assertEqual(manifest["status"], "ERROR")
        self.assertIn("installation failed", manifest["error"])

    def test_malformed_output_records_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)

            def malformed(target, output_path):
                output_path.write_text("not-json", encoding="utf-8")
                return []

            with patch.dict(
                "security_system.application.scanner_job.SCANNERS",
                {"semgrep": malformed},
                clear=False,
            ):
                manifest = run_scanner_job("semgrep", Path("."), output)

            self.assertEqual(manifest["status"], "ERROR")

    def test_empty_changed_file_scope_writes_empty_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            with patch(
                "security_system.application.scanner_job.resolve_changed_file_scope",
                return_value=ChangedFileScope(
                    mode="diff",
                    base="base",
                    head="head",
                    changed_files=[],
                    skipped_deleted_count=1,
                ),
            ):
                manifest = run_scanner_job("trivy", Path("."), output, changed_only=True)

            self.assertEqual(manifest["status"], "COMPLETED")
            self.assertEqual(manifest["scan_scope"]["changed_file_count"], 0)
            self.assertEqual(manifest["scan_scope"]["skipped_deleted_count"], 1)
            self.assertEqual(json.loads((output / "trivy-report.json").read_text()), {"Results": []})

    def test_changed_only_passes_changed_files_to_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            calls = {}

            def scanner(target, output_path, changed_files):
                calls["target"] = target
                calls["changed_files"] = changed_files
                output_path.write_text("[]", encoding="utf-8")
                return []

            with patch(
                "security_system.application.scanner_job.resolve_changed_file_scope",
                return_value=ChangedFileScope(
                    mode="diff",
                    base="base",
                    head="head",
                    changed_files=["PokeMap/src/client/package.json"],
                ),
            ), patch.dict(
                "security_system.application.scanner_job.SCANNERS",
                {"gitleaks": scanner},
                clear=False,
            ):
                manifest = run_scanner_job("gitleaks", Path("."), output, changed_only=True)

            self.assertEqual(manifest["status"], "COMPLETED")
            self.assertEqual(calls["changed_files"], ["PokeMap/src/client/package.json"])
            self.assertEqual(manifest["scan_scope"]["base"], "base")
            self.assertEqual(manifest["scan_scope"]["head"], "head")


class ChangedFileScopeTest(unittest.TestCase):
    def test_parse_name_status_skips_deleted_and_uses_new_rename_path(self) -> None:
        changed, deleted = _parse_name_status([
            "A\tadded.js",
            "M\tmodified.py",
            "D\tdeleted.txt",
            "R100\told-name.js\tnew-name.js",
            "C100\tsource.js\tcopy.js",
            "T\ttype-changed.yml",
        ])

        self.assertEqual(changed, [
            "added.js",
            "modified.py",
            "new-name.js",
            "copy.js",
            "type-changed.yml",
        ])
        self.assertEqual(deleted, 1)


class ScannerReportNormalizationTest(unittest.TestCase):
    def test_gitleaks_paths_are_rewritten_from_mirror_to_repo_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mirror = Path(tmp)
            raw = [{"File": str(mirror / "PokeMap/src/client/.env"), "Path": str(mirror / "a/b.js")}]

            normalized = normalize_gitleaks_paths(raw, mirror)

            self.assertEqual(normalized[0]["File"], "PokeMap/src/client/.env")
            self.assertEqual(normalized[0]["Path"], "a/b.js")

    def test_semgrep_absolute_paths_are_rewritten_to_repo_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            raw = {"results": [{"path": str(repo / "src/app.jsx")}]}

            normalized = normalize_semgrep_paths(raw, repo)

            self.assertEqual(normalized["results"][0]["path"], "src/app.jsx")

    def test_trivy_targets_are_rewritten_from_mirror_to_repo_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mirror = Path(tmp)
            raw = {"Results": [{"Target": str(mirror / "PokeMap/src/client/package-lock.json")}]}

            normalized = normalize_trivy_paths(raw, mirror)

            self.assertEqual(normalized["Results"][0]["Target"], "PokeMap/src/client/package-lock.json")


class ScannerWrapperCommandTest(unittest.TestCase):
    def test_gitleaks_changed_files_uses_dir_mode_not_git_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "app").mkdir()
            (repo / "app/config.js").write_text("const token = 'fake';", encoding="utf-8")
            output = repo / "report.json"
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                report_path = Path(cmd[cmd.index("--report-path") + 1])
                report_path.write_text("[]", encoding="utf-8")
                return type("Result", (), {"returncode": 0, "stderr": ""})()

            with patch("security_system.infrastructure.scanners.gitleaks.subprocess.run", side_effect=fake_run):
                findings = run_gitleaks(repo, output_path=output, changed_files=["app/config.js"])

            self.assertEqual(findings, [])
            self.assertEqual(calls[0][0:2], ["gitleaks", "dir"])
            self.assertNotIn("--source", calls[0])
            self.assertNotIn("detect", calls[0])

    def test_semgrep_changed_files_are_passed_as_file_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "app").mkdir()
            (repo / "app/view.jsx").write_text("export default null;", encoding="utf-8")
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                report_path = Path(cmd[cmd.index("--output") + 1])
                report_path.write_text('{"results": []}', encoding="utf-8")
                return type("Result", (), {"returncode": 0, "stderr": ""})()

            with patch("security_system.infrastructure.scanners.semgrep.subprocess.run", side_effect=fake_run):
                findings = run_semgrep(repo, changed_files=["app/view.jsx"])

            self.assertEqual(findings, [])
            self.assertIn(str(repo / "app/view.jsx"), calls[0])
            self.assertNotIn(str(repo), calls[0][-1:])

    def test_trivy_changed_files_scans_temporary_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "app").mkdir()
            (repo / "app/package-lock.json").write_text("{}", encoding="utf-8")
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                report_path = Path(cmd[cmd.index("--output") + 1])
                report_path.write_text('{"Results": []}', encoding="utf-8")
                return type("Result", (), {"returncode": 0, "stderr": ""})()

            with patch("security_system.infrastructure.scanners.trivy.subprocess.run", side_effect=fake_run):
                findings = run_trivy(repo, changed_files=["app/package-lock.json"])

            self.assertEqual(findings, [])
            self.assertEqual(calls[0][0:2], ["trivy", "fs"])
            self.assertNotEqual(Path(calls[0][-1]).resolve(), repo.resolve())


class AggregationPipelineTest(unittest.TestCase):
    def _run(self, scanner_dir: Path, reports_dir: Path):
        with patch(
            "security_system.application.aggregate_pipeline.GitService.get_context",
            return_value=GitContext.empty(),
        ), patch(
            "security_system.application.aggregate_pipeline.analyze",
            side_effect=_unavailable_analysis,
        ):
            return run_aggregation(scanner_dir, reports_dir)

    def test_empty_successful_reports_pass(self) -> None:
        with tempfile.TemporaryDirectory() as scans, tempfile.TemporaryDirectory() as reports:
            scanner_dir = Path(scans)
            _empty_reports(scanner_dir)
            for tool in ("gitleaks", "semgrep", "trivy"):
                _manifest(scanner_dir, tool)

            decision = self._run(scanner_dir, Path(reports))

            self.assertEqual(decision.decision, "PASS")

    def test_high_and_medium_findings_fail_and_block_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as scans, tempfile.TemporaryDirectory() as reports:
            scanner_dir = Path(scans)
            _empty_reports(scanner_dir)
            semgrep = {
                "results": [{
                    "check_id": f"rule-{index}",
                    "severity": "WARNING",
                    "path": "app.py",
                    "start": {"line": index + 1},
                    "extra": {"message": "medium finding"},
                } for index in range(7)]
            }
            trivy = {"Results": [{
                "Target": "package-lock.json",
                "Vulnerabilities": [{
                    "VulnerabilityID": f"CVE-{index}",
                    "PkgName": "pkg",
                    "Severity": "HIGH",
                    "Title": "high finding",
                } for index in range(21)],
            }]}
            (scanner_dir / "semgrep-report.json").write_text(json.dumps(semgrep), encoding="utf-8")
            (scanner_dir / "trivy-report.json").write_text(json.dumps(trivy), encoding="utf-8")
            for tool in ("gitleaks", "semgrep", "trivy"):
                _manifest(scanner_dir, tool)

            reports_dir = Path(reports)
            decision = self._run(scanner_dir, reports_dir)
            monitor = json.loads((reports_dir / "monitor_report.json").read_text())

            self.assertEqual(decision.decision, "FAIL")
            self.assertEqual(decision.exit_code(), 1)
            self.assertEqual(monitor["pipeline_status"], "BLOCKED")
            self.assertEqual(monitor["findings_by_severity"]["HIGH"], 21)
            self.assertEqual(monitor["findings_by_severity"]["MEDIUM"], 7)

    def test_failed_scanner_preserves_available_findings_and_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as scans, tempfile.TemporaryDirectory() as reports:
            scanner_dir = Path(scans)
            _empty_reports(scanner_dir)
            semgrep = {"results": [{
                "check_id": "rule",
                "severity": "WARNING",
                "path": "app.py",
                "start": {"line": 1},
                "extra": {"message": "medium finding"},
            }]}
            (scanner_dir / "semgrep-report.json").write_text(json.dumps(semgrep), encoding="utf-8")
            _manifest(scanner_dir, "gitleaks")
            _manifest(scanner_dir, "semgrep")
            _manifest(scanner_dir, "trivy", "ERROR", "scanner timed out")

            reports_dir = Path(reports)
            decision = self._run(scanner_dir, reports_dir)
            summary = json.loads((reports_dir / "summary.json").read_text())
            monitor = json.loads((reports_dir / "monitor_report.json").read_text())

            self.assertEqual(decision.decision, "FAIL")
            self.assertEqual(summary["by_severity"]["MEDIUM"], 1)
            self.assertEqual(monitor["pipeline_status"], "ERROR")

    def test_missing_or_malformed_artifact_fails_closed(self) -> None:
        for malformed in (False, True):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as scans, tempfile.TemporaryDirectory() as reports:
                scanner_dir = Path(scans)
                _empty_reports(scanner_dir)
                _manifest(scanner_dir, "gitleaks")
                _manifest(scanner_dir, "semgrep")
                if malformed:
                    _manifest(scanner_dir, "trivy")
                    (scanner_dir / "trivy-report.json").write_text("bad-json", encoding="utf-8")

                decision = self._run(scanner_dir, Path(reports))

                self.assertEqual(decision.decision, "FAIL")
                monitor = json.loads((Path(reports) / "monitor_report.json").read_text())
                self.assertEqual(monitor["pipeline_status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
