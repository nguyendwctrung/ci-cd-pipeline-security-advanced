# Security System

## System Architecture

```text
Developer
   |
   | Push / Pull Request / Manual or Scheduled Run
   v
GitHub Actions Security Pipeline
   |
   +-- Configure Git diff context
   +-- Install Gitleaks, Semgrep, and Trivy
   +-- Run security_system
   |
   v
security_system
   |
   +-- Git context collection
   +-- Scanner execution
   +-- Report parsing
   +-- Deterministic policy evaluation
   +-- Optional Gemini analysis
   +-- Final decision merging
   +-- Report and monitoring generation
   |
   +--> GitHub artifact reports
   +--> GitHub job summary
   +--> CI security gate
   |
   +--> monitor_report.json
            |
            | Timestamped HMAC request
            v
security_dashboard FastAPI Backend on Vercel
            |
            | Validate signature and sanitize report
            v
MongoDB Atlas
            |
            v
Streamlit Security Dashboard
```

## 1. GitHub Actions Pipeline

The workflow is defined in `.github/workflows/security-scan.yml`

Responsibilities:

- Runs on pushes and pull requests to main and dev.
- Supports scheduled and manual runs.
- Checks out the full Git history.
- Configures the commit comparison range.
- Installs pinned scanner dependencies.
- Starts the unified Python security pipeline.
- Uploads reports and logs as GitHub artifacts.
- Writes a security summary to the workflow page.
- Publishes monitoring data to FastAPI.
- Creates GitHub issue alerts for infrastructure errors.

Monitoring publication is non-blocking and does not change the security decision.

## 2. Security System

`security_system` contains the security logic and scanner orchestration.

Main processing stages:

```text
Git context
    ↓
Run scanners
    ↓
Parse findings
    ↓
Apply scanner policy
    ↓
Optional Gemini analysis
    ↓
Merge decisions
    ↓
Generate reports
```

Scanner components:

- **Gitleaks** detects committed secrets and credentials.
- **Semgrep** performs static code security analysis.
- **Trivy** detects dependency vulnerabilities and filesystem misconfigurations.

Policy rules:

```text
Any Gitleaks finding → FAIL
Any CRITICAL finding → FAIL
Any HIGH finding     → WARN
Otherwise            → PASS
Scanner failure      → FAIL / pipeline ERROR
```

The scanner policy is authoritative and does not depend on Gemini.

## 3. Gemini Analysis

Gemini is an optional advisory component.

It receives:

- Sanitized scanner findings
- Git change context
- Finding summaries

It returns:

- recommended_decision: PASS, WARN, or FAIL
- Risk category
- Malicious-code indication
- Detected patterns
- Recommendations
- Reasoning

The final decision uses the stricter result:

```text
Scanner policy PASS + Gemini WARN → WARN
Scanner policy WARN + Gemini PASS → WARN
Scanner policy FAIL + Gemini PASS → FAIL
Scanner policy PASS + Gemini FAIL → FAIL
```

If Gemini is unavailable, scanner policy remains fully operational.

## 4. Generated Reports

The pipeline creates reports under `security_system/reports/artifacts`:

- `gitleaks-report.json`
- `semgrep-report.json`
- `trivy-report.json`
- `summary.json`
- `ai_analysis.json`
- `decision_report.json`
- `monitor_report.json`

Raw scanner reports remain in protected GitHub artifacts. Only sanitized monitoring data is published externally.

## 5. Monitoring Instrumentation

The monitor records:

- Pipeline and stage status
- Stage durations
- Scanner availability
- Findings by scanner and severity
- Policy, Gemini, and final decisions
- Gemini availability
- Commit and GitHub workflow metadata
- Sanitized errors

Overall monitoring states are:

- `COMPLETED`: pipeline finished without a blocking policy decision
- `BLOCKED`: security policy produced `FAIL`
- `ERROR`: scanner or pipeline infrastructure malfunctioned

## 6. FastAPI Monitoring Backend

The backend is deployed on Vercel.

Endpoints:

```text
GET  /health
POST /api/v1/runs
```

For ingestion, GitHub Actions sends:

```text
monitor_report.json
+ request timestamp
+ HMAC signature
```

FastAPI:

- Verifies the timestamp and HMAC signature.
- Rejects invalid, expired, or replayed requests.
- Validates the report schema.
- Removes unsupported or sensitive fields.
- Upserts the run by GitHub run ID.
- Returns HTTP 202 when accepted.

## 7. MongoDB Atlas

MongoDB is the monitoring history database.

Collections:

- `security_runs`: sanitized pipeline records
- `ingestion_signatures`: replay-protection records

MongoDB does not store:

- PokeMap application data
- Source code
- Raw findings
- Secrets
- Gemini prompts

Monitoring records are retained for approximately 90 days.

## 8. Streamlit Dashboard

The standalone Streamlit dashboard reads monitoring data directly from MongoDB Atlas.

It displays:

- Latest pipeline status
- Scanner health
- Policy and final decisions
- Findings by scanner and severity
- Ordered severity chart
- Pipeline duration trends
- Gemini availability
- Searchable run history
- Individual stage details
- GitHub Actions links

The dashboard is password-protected and independent of PokeMap.

End-to-End Workflow

```text
1. Developer pushes code.

2. GitHub Actions starts the security workflow.

3. The workflow installs and verifies security tools.

4. security_system collects Git context.

5. Gitleaks, Semgrep, and Trivy scan the repository.

6. Scanner reports are parsed into normalized findings.

7. Deterministic policy produces PASS, WARN, or FAIL.

8. Gemini optionally provides an advisory recommendation.

9. The stricter policy/Gemini decision becomes final.

10. GitHub Actions enforces the final decision.

11. Reports are uploaded as GitHub artifacts.

12. monitor_report.json is signed and sent to FastAPI.

13. FastAPI validates and stores the report in MongoDB Atlas.

14. Streamlit reads the stored data and displays pipeline history.
```
