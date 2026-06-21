from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from security_system.application.use_cases.run_scan import ScanOutput
from security_system.benchmark.config import load_repos
from security_system.benchmark.ground_truth import seed_ground_truth_from_findings
from security_system.benchmark.models import BenchmarkPaths, RepoSpec
from security_system.benchmark.normalize import issue_to_benchmark_finding, normalize_scan_output
from security_system.benchmark.repository import CheckoutResult
from security_system.benchmark.runner import BenchmarkRunner
from security_system.benchmark.scoring import score_repository
from security_system.domain.models import SecurityIssue, Severity


class BenchmarkConfigTest(unittest.TestCase):
    def test_load_repos_validates_required_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "repos.yaml"
            path.write_text(
                """
repositories:
  - name: sample
    url: https://example.test/repo.git
    commit: 0123456789abcdef0123456789abcdef01234567
    language: python
    category: vulnerable_app
    enabled_checks: [sast, secret]
""",
                encoding="utf-8",
            )

            repos = load_repos(path)

        self.assertEqual(len(repos), 1)
        self.assertEqual(repos[0].name, "sample")
        self.assertEqual(repos[0].enabled_checks, ["sast", "secret"])

    def test_load_repos_rejects_non_sha_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "repos.yaml"
            path.write_text(
                """
repositories:
  - name: sample
    url: https://example.test/repo.git
    commit: main
    language: python
    category: vulnerable_app
    enabled_checks: [sast]
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "commit must be"):
                load_repos(path)


class BenchmarkNormalizeTest(unittest.TestCase):
    def test_issue_to_benchmark_finding_preserves_core_fields(self) -> None:
        issue = SecurityIssue(
            tool="gitleaks",
            severity=Severity.HIGH,
            type="generic-api-key",
            message="secret found",
            file="config.env",
            line=7,
        )

        finding = issue_to_benchmark_finding("repo", issue)

        self.assertEqual(finding.repo, "repo")
        self.assertEqual(finding.rule_id, "generic-api-key")
        self.assertEqual(finding.category, "secret")
        self.assertEqual(finding.confidence, "medium")

    def test_semgrep_cwe_metadata_is_preserved_when_available(self) -> None:
        issue = SecurityIssue(
            tool="semgrep",
            severity=Severity.HIGH,
            type="python.sql-injection",
            message="sql injection",
            file="app.py",
            line=12,
        )
        scan_output = ScanOutput(
            raw_data={
                "semgrep": [{
                    "check_id": "python.sql-injection",
                    "path": "app.py",
                    "start": {"line": 12},
                    "extra": {"metadata": {"cwe": "CWE-89"}},
                }]
            },
            all_issues=[issue],
        )

        findings = normalize_scan_output("repo", scan_output)

        self.assertEqual(findings[0].cwe, "CWE-89")
        self.assertEqual(findings[0].category, "sql-injection")


class BenchmarkScoringTest(unittest.TestCase):
    def test_scores_legacy_csv_without_rule_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "repo.findings.json"
            findings.write_text(json.dumps([
                {
                    "repo": "repo",
                    "tool": "semgrep",
                    "rule_id": "python.sql-injection",
                    "category": "sql-injection",
                    "cwe": "CWE-89",
                    "severity": "HIGH",
                    "file": "app.py",
                    "line": 15,
                    "message": "sql injection",
                    "confidence": "medium",
                },
                {
                    "repo": "repo",
                    "tool": "semgrep",
                    "rule_id": "python.xss",
                    "category": "xss",
                    "cwe": "CWE-79",
                    "severity": "MEDIUM",
                    "file": "view.py",
                    "line": 40,
                    "message": "xss",
                    "confidence": "medium",
                },
            ]), encoding="utf-8")
            truth = root / "truth.csv"
            truth.write_text(
                "repo,vuln_id,type,cwe,file,line,severity\n"
                "repo,V1,sql-injection,CWE-89,app.py,12,HIGH\n"
                "repo,V2,command-injection,CWE-78,shell.py,8,HIGH\n",
                encoding="utf-8",
            )

            score = score_repository(findings, truth)

        self.assertEqual(score["strict"]["tp"], 1)
        self.assertEqual(score["strict"]["fp"], 1)
        self.assertEqual(score["strict"]["fn"], 1)
        self.assertEqual(score["relaxed"]["tp"], 1)
        self.assertEqual(score["category"]["tp"], 1)

    def test_rule_id_distinguishes_dependency_findings_in_same_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "repo.findings.json"
            findings.write_text(json.dumps([
                {
                    "repo": "repo",
                    "tool": "trivy",
                    "rule_id": "CVE-2026-0001",
                    "category": "dependency",
                    "cwe": None,
                    "severity": "HIGH",
                    "file": "requirements.txt",
                    "line": None,
                    "message": "vuln one",
                    "confidence": "medium",
                },
                {
                    "repo": "repo",
                    "tool": "trivy",
                    "rule_id": "CVE-2026-0002",
                    "category": "dependency",
                    "cwe": None,
                    "severity": "HIGH",
                    "file": "requirements.txt",
                    "line": None,
                    "message": "vuln two",
                    "confidence": "medium",
                },
            ]), encoding="utf-8")
            truth = root / "truth.csv"
            truth.write_text(
                "repo,vuln_id,type,rule_id,cwe,file,line,severity\n"
                "repo,V1,dependency,CVE-2026-0001,,requirements.txt,,HIGH\n"
                "repo,V2,dependency,CVE-2026-0002,,requirements.txt,,HIGH\n",
                encoding="utf-8",
            )

            score = score_repository(findings, truth)

        self.assertEqual(score["strict"]["tp"], 2)
        self.assertEqual(score["strict"]["fp"], 0)
        self.assertEqual(score["strict"]["fn"], 0)
        self.assertEqual(score["relaxed"]["tp"], 2)
        self.assertEqual(score["category"]["tp"], 2)

    def test_mixed_old_header_new_rows_do_not_shift_line_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "repo.findings.json"
            findings.write_text(json.dumps([{
                "repo": "repo",
                "tool": "trivy",
                "rule_id": "CVE-2026-0001",
                "category": "dependency",
                "cwe": None,
                "severity": "HIGH",
                "file": "requirements.txt",
                "line": None,
                "message": "vuln one",
                "confidence": "medium",
            }]), encoding="utf-8")
            truth = root / "truth.csv"
            truth.write_text(
                "repo,vuln_id,type,cwe,file,line,severity\n"
                "repo,V1,dependency,CVE-2026-0001,,requirements.txt,,HIGH\n",
                encoding="utf-8",
            )

            score = score_repository(findings, truth)

        self.assertEqual(score["strict"]["tp"], 1)


class BenchmarkGroundTruthSeedTest(unittest.TestCase):
    def _repo(self) -> RepoSpec:
        return RepoSpec(
            name="dvwa",
            url="https://example.test/dvwa.git",
            commit="0123456789abcdef0123456789abcdef01234567",
            language="php",
            category="vulnerable_app",
            enabled_checks=["secret"],
            ground_truth="dvwa.csv",
        )

    def test_seed_ground_truth_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "dvwa.findings.json"
            findings.write_text(json.dumps([{
                "repo": "dvwa",
                "tool": "gitleaks",
                "rule_id": "generic-api-key",
                "category": "secret",
                "cwe": None,
                "severity": "HIGH",
                "file": "config.php",
                "line": 4,
                "message": "secret",
                "confidence": "medium",
            }]), encoding="utf-8")

            result = seed_ground_truth_from_findings(self._repo(), findings, root, write=False)

        self.assertEqual(result.added, 1)
        self.assertFalse(result.path.exists())

    def test_seed_ground_truth_writes_and_skips_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "dvwa.findings.json"
            findings.write_text(json.dumps([{
                "repo": "dvwa",
                "tool": "gitleaks",
                "rule_id": "generic-api-key",
                "category": "secret",
                "cwe": None,
                "severity": "HIGH",
                "file": "config.php",
                "line": 4,
                "message": "secret",
                "confidence": "medium",
            }]), encoding="utf-8")

            first = seed_ground_truth_from_findings(self._repo(), findings, root, write=True)
            second = seed_ground_truth_from_findings(self._repo(), findings, root, write=True)
            content = (root / "dvwa.csv").read_text(encoding="utf-8")

        self.assertEqual(first.added, 1)
        self.assertEqual(second.added, 0)
        self.assertEqual(second.skipped_existing, 1)
        self.assertIn("rule_id", content)
        self.assertIn("generic-api-key", content)
        self.assertIn("CWE-798", content)

    def test_seed_ground_truth_duplicate_key_includes_rule_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "dvwa.findings.json"
            findings.write_text(json.dumps([
                {
                    "repo": "dvwa",
                    "tool": "trivy",
                    "rule_id": "CVE-1",
                    "category": "dependency",
                    "cwe": None,
                    "severity": "HIGH",
                    "file": "requirements.txt",
                    "line": None,
                    "message": "one",
                    "confidence": "medium",
                },
                {
                    "repo": "dvwa",
                    "tool": "trivy",
                    "rule_id": "CVE-2",
                    "category": "dependency",
                    "cwe": None,
                    "severity": "HIGH",
                    "file": "requirements.txt",
                    "line": None,
                    "message": "two",
                    "confidence": "medium",
                },
            ]), encoding="utf-8")

            result = seed_ground_truth_from_findings(self._repo(), findings, root, write=True)
            content = (root / "dvwa.csv").read_text(encoding="utf-8")

        self.assertEqual(result.added, 2)
        self.assertIn("CVE-1", content)
        self.assertIn("CVE-2", content)

    def test_seed_ground_truth_rewrites_old_schema_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dvwa.csv").write_text(
                "repo,vuln_id,type,cwe,file,line,severity\n"
                "dvwa,OLD-1,secret,CWE-798,config.php,4,HIGH\n",
                encoding="utf-8",
            )
            findings = root / "dvwa.findings.json"
            findings.write_text(json.dumps([{
                "repo": "dvwa",
                "tool": "gitleaks",
                "rule_id": "generic-api-key",
                "category": "secret",
                "cwe": None,
                "severity": "HIGH",
                "file": "other.php",
                "line": 5,
                "message": "secret",
                "confidence": "medium",
            }]), encoding="utf-8")

            seed_ground_truth_from_findings(self._repo(), findings, root, write=True)
            content = (root / "dvwa.csv").read_text(encoding="utf-8")

        self.assertTrue(content.startswith("repo,vuln_id,type,rule_id,cwe,file,line,severity"))
        self.assertIn("OLD-1,secret,,CWE-798,config.php,4,HIGH", content)
        self.assertIn("generic-api-key", content)


class BenchmarkRunnerTest(unittest.TestCase):
    def _repo(self, name: str = "repo") -> RepoSpec:
        return RepoSpec(
            name=name,
            url="https://example.test/repo.git",
            commit="0123456789abcdef0123456789abcdef01234567",
            language="python",
            category="vulnerable_app",
            enabled_checks=["sast"],
        )

    def test_existing_normalized_output_is_skipped_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = BenchmarkPaths.from_root(Path(tmp))
            paths.normalized_dir.mkdir(parents=True)
            (paths.normalized_dir / "repo.findings.json").write_text("[]", encoding="utf-8")
            runner = BenchmarkRunner(paths)
            runner.repo_manager.prepare = Mock(side_effect=AssertionError("prepare should not run"))

            record = runner.run_one(self._repo(), force=False)

        self.assertEqual(record["status"], "SKIPPED")

    def test_failed_repository_does_not_stop_run_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = BenchmarkPaths.from_root(Path(tmp))
            runner = BenchmarkRunner(paths)

            def prepare(repo: RepoSpec) -> CheckoutResult:
                if repo.name == "bad":
                    return CheckoutResult(repo=repo.name, path=Path(tmp) / repo.name, status="ERROR", commit=repo.commit, error="clone failed")
                return CheckoutResult(repo=repo.name, path=Path(tmp) / repo.name, status="READY", commit=repo.commit)

            runner.repo_manager.prepare = prepare  # type: ignore[method-assign]
            runner._run_pipeline_subprocess = Mock(return_value={"status": "COMPLETED", "error": ""})  # pylint: disable=protected-access
            with patch("security_system.benchmark.runner.load_scan_output", return_value=ScanOutput()):
                records = runner.run_many([self._repo("good"), self._repo("bad")], force=True)

        self.assertEqual([record["status"] for record in records], ["COMPLETED", "ERROR"])

    def test_force_reruns_existing_normalized_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = BenchmarkPaths.from_root(Path(tmp))
            paths.normalized_dir.mkdir(parents=True)
            (paths.normalized_dir / "repo.findings.json").write_text("[]", encoding="utf-8")
            runner = BenchmarkRunner(paths)
            runner.repo_manager.prepare = Mock(return_value=CheckoutResult(
                repo="repo",
                path=Path(tmp) / "repo",
                status="READY",
                commit="0123456789abcdef0123456789abcdef01234567",
            ))
            runner._run_pipeline_subprocess = Mock(return_value={"status": "COMPLETED", "error": ""})  # pylint: disable=protected-access
            with patch("security_system.benchmark.runner.load_scan_output", return_value=ScanOutput()):
                record = runner.run_one(self._repo(), force=True)

        self.assertEqual(record["status"], "COMPLETED")
        runner.repo_manager.prepare.assert_called_once()


if __name__ == "__main__":
    unittest.main()