# Summary

## System Architecture

![Security System Architecture](/images/architecture.png)

## Tools Used

| Tool | Purpose |
| --- | --- |
| GitHub Actions | Runs the CI/CD security scan workflow on push, pull request, scheduled runs, and manual dispatch. |
| Gitleaks | Detects committed secrets and credential leaks. |
| Semgrep | Performs static application security testing using code rules. |
| Trivy | Scans dependencies, filesystems, and configuration for known vulnerabilities and security issues. |
| Google Gemini API | Performs LLM-assisted security analysis of scanner findings and git context. |
| FastAPI | Provides the monitoring ingestion API for sanitized pipeline reports. |
| Streamlit | Provides the private security monitoring dashboard. |
| MongoDB Atlas | Stores sanitized monitoring history for dashboard reporting and trend analysis. |

## Components

### CI/CD Security Workflow

The workflow is defined in `.github/workflows/security-scan.yml`. It triggers on:

- Pushes to `main` and `dev`
- Pull requests targeting `main` and `dev`
- Daily scheduled runs
- Manual workflow dispatch

The workflow has two main jobs:

- `scan`: runs Gitleaks, Semgrep, and Trivy in parallel matrix jobs.
- `aggregate`: downloads scanner artifacts, aggregates results, runs LLM analysis, makes the final security decision, uploads reports, comments on pull requests, and optionally publishes monitoring data.

### Application Layer

The application layer coordinates use cases without holding security business rules.

| Component | Responsibility |
| --- | --- |
| `security_system.application.scanner_job` | Runs one scanner job in CI and writes a scanner report plus a manifest for aggregation. |
| `security_system.application.changed_files` | Resolves changed files from the configured git diff so CI scans can focus on changed files. |
| `security_system.application.use_cases.run_scan` | Runs all scanners locally or loads scanner reports and normalizes them into scan output. |
| `security_system.application.use_cases.analyze` | Sends scan findings and git context to the LLM analyzer, with fallback when Gemini is unavailable. |
| `security_system.application.use_cases.make_decision` | Combines policy decision and LLM decision into the final gate result. |
| `security_system.application.pipeline` | Runs the full local sequential pipeline. |
| `security_system.application.aggregate_pipeline` | Aggregates parallel CI scanner outputs into final reports and decisions. |
| `security_system.application.monitoring` | Records stage timing, scanner health, findings, decisions, and errors. |
| `security_system.application.monitor_reporting` | Renders GitHub step summaries and publishes sanitized monitoring reports. |

### Domain Layer

The domain layer contains normalized models, parsers, analysis rules, and decision logic.

| Component | Responsibility |
| --- | --- |
| `domain.models.SecurityIssue` | Normalized finding model used across tools. |
| `domain.models.GitContext` | Commit metadata used by analysis and reports. |
| `domain.models.AnalysisResult` | LLM analysis output model. |
| `domain.models.DecisionReport` | Final PASS, WARN, or FAIL result model. |
| `domain.parsers.GitleaksParser` | Converts Gitleaks JSON into normalized security issues. |
| `domain.parsers.SemgrepParser` | Converts Semgrep JSON into normalized security issues. |
| `domain.parsers.TrivyParser` | Converts Trivy JSON into normalized security issues. |
| `domain.analysis.LLMAnalyzer` | Builds security analysis from scanner findings and git context using an injected LLM provider. |
| `domain.decision.PolicyEngine` | Applies deterministic scanner policy rules. |
| `domain.decision.DecisionEngine` | Converts LLM analysis and scan summaries into a decision report. |
| `domain.services.GitService` | Collects commit, branch, author, and repository context. |

### Infrastructure Layer

The infrastructure layer adapts external tools and persistence.

| Component | Responsibility |
| --- | --- |
| `infrastructure.scanners.gitleaks` | Runs the Gitleaks CLI and writes JSON output. |
| `infrastructure.scanners.semgrep` | Runs the Semgrep CLI and writes JSON output. |
| `infrastructure.scanners.trivy` | Runs the Trivy CLI and writes JSON output. |
| `infrastructure.llm.GeminiProvider` | Connects the domain analyzer to the Google Gemini API. |
| `infrastructure.storage.ArtifactStore` | Saves raw scanner reports and final pipeline artifacts. |
| `infrastructure.storage.file_store` | Provides filesystem helpers for JSON report persistence. |

### Monitoring System

The monitoring system stores and displays sanitized security pipeline history.

| Component | Responsibility |
| --- | --- |
| `security_dashboard.backend` | FastAPI service that receives signed monitoring reports from GitHub Actions. |
| `security_dashboard.backend.app.auth` | Verifies HMAC signatures and prevents unauthorized ingestion. |
| `security_dashboard.backend.app.repository` | Stores run history and findings in MongoDB Atlas. |
| `security_dashboard.dashboard` | Password-protected Streamlit dashboard for pipeline status, scanner health, findings, trends, and run history. |

Raw scanner reports, source snippets, secrets, and Gemini prompts remain in protected GitHub Actions artifacts. The monitoring system only receives sanitized operational data.

## End-to-End Workflow

1. A developer pushes code, opens a pull request, manually starts the workflow, or the scheduled scan runs.

2. GitHub Actions checks out the repository and computes the diff context:
   - Pull requests use the PR base SHA and head SHA.
   - Push events use the previous commit and current commit.
   - If no previous commit is available, the workflow falls back to the parent commit or an empty tree.

3. The `scan` job runs three parallel scanner jobs:
   - Gitleaks checks for leaked secrets.
   - Semgrep checks code patterns and static security rules.
   - Trivy checks vulnerabilities and filesystem/configuration issues.

4. Each scanner job writes:
   - A raw scanner JSON report.
   - A scanner manifest with status, duration, report name, error information, and scan scope.

5. The `aggregate` job downloads all scanner artifacts into the scanner results directory.

6. `aggregate_pipeline` validates scanner manifests and report files:
   - If a manifest is missing, malformed, or reports scanner failure, the pipeline records the scanner failure.
   - Failed or missing scanner reports are replaced with empty normalized reports so aggregation can still produce a complete failure decision.

7. The scanner reports are parsed and normalized:
   - Gitleaks findings, Semgrep findings, and Trivy findings are converted into common `SecurityIssue` records.
   - Per-tool summaries and severity counts are built.
   - All normalized findings are flattened for policy evaluation.

8. Git context is collected:
   - Commit hash
   - Branch
   - Author
   - Repository metadata

9. Gemini analysis runs when `GOOGLE_API_KEY` is configured:
   - Scanner raw data and git context are sent to the domain analyzer.
   - The analyzer returns risk level, malicious intent assessment, detected patterns, recommendations, and a recommended decision.
   - If Gemini is unavailable, the system records a fallback analysis and continues using deterministic policy rules.

10. The policy engine evaluates normalized findings using these rules:
    - Any Gitleaks secret causes `FAIL`.
    - Any `CRITICAL` issue causes `FAIL`.
    - Any `HIGH` issue causes `FAIL`.
    - Any `MEDIUM` issue causes `WARN`.
    - No blocking findings causes `PASS`.

11. The final decision is produced:
    - Scanner policy is authoritative.
    - LLM analysis can make the result stricter when available.
    - Unavailable or failed LLM analysis cannot weaken or raise the scanner policy result.

12. The pipeline writes final artifacts:
    - `summary.json`
    - `ai_analysis.json`
    - `decision_report.json`
    - `monitor_report.json`
    - `security-pipeline.log`

13. GitHub Actions uploads the security artifacts with 30-day retention.

14. GitHub Actions writes a security monitoring summary to the workflow run summary.

15. For pull requests, GitHub Actions posts a comment with:
    - LLM availability
    - LLM recommendation
    - Risk level
    - Malicious flag
    - Final PASS, WARN, or FAIL decision
    - Policy decision, LLM decision, and decision source

16. The workflow publishes `monitor_report.json` to the FastAPI monitoring backend:
    - The request is signed with HMAC.
    - The backend validates the signature and timestamp.
    - The backend validates the report schema.
    - The backend rejects duplicate ingestion requests.
    - The backend stores the sanitized report in MongoDB Atlas.

17. The Streamlit dashboard reads from MongoDB Atlas and displays:
    - Latest pipeline status
    - Final decision
    - Findings by severity
    - Scanner health
    - Pipeline duration trends
    - Gemini availability
    - Detailed sanitized findings
    - Historical run records

18. The workflow exit code enforces the security gate:
    - `PASS` allows the pipeline to proceed.
    - `WARN` records a warning state.
    - `FAIL` blocks the pipeline until findings or scanner failures are resolved.
