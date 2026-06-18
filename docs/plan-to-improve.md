# System Improvement Plan

## Objectives

The primary objective is to upgrade the current security system from a single-repository execution level to a multi-repository evaluation framework, backed by clear quantitative metrics to demonstrate its effectiveness.

Specifically, the following must be achieved:

### 1. Expand Evaluation Scope

- Move beyond testing on a single internal repository.
- Support execution across multiple repositories varying in languages, frameworks, scales, and types of security vulnerabilities.

### 2. Standardize the Benchmark Process

- Ensure every repository is cloned, checked out to the correct commit, scanned, and logged using an identical workflow.
- Guarantee that all results are reproducible.

### 3. Measure with Specific Metrics

- Calculate Precision, Recall, and F1-score for repositories with ground truth.
- Track False Positive Rate for production (real-world) repositories.
- Monitor Runtime, number of findings, severity distribution, and CI overhead.

### 4. Compare Against Baseline Tools

- Benchmarking the current system against industry-standard tools such as Semgrep, CodeQL, Trivy, Gitleaks, and Checkov.
- Identify the system's specific strengths and weaknesses based on these comparisons.

### 5. Drive System Improvements Based on Results

- Add missing security rules.
- Reduce false positives.
- Standardize output formats.
- Optimize scan execution times.
- Enhance CI/CD pipeline integration capabilities.

## End-to-End Implementation Plan

### Phase 1: Current System Assessment

The goal of this phase is to thoroughly understand what the current system can and cannot achieve.

Tasks to execute:

#### 1. Map Current Security Check Capabilities

Identify which vulnerability categories the system currently scans for:

- SAST/code vulnerability.
- Dependency vulnerability.
- Secret scanning.
- Docker/Kubernetes/IaC misconfiguration.
- CI/CD workflow security.
- Policy compliance.

#### 2. Audit Current Input/Output Mechanisms

- How does the system ingest a repository? Is manual configuration required?
- What is the output format (JSON, HTML, SARIF, text logs)? Does it include Rule ID, severity, file path, line number, and CWE?

#### 3. Identify Bottlenecks and Limitations

Is it hard-coded for a single repo? Does it lack multi-language support? Is there no standardized report schema? Does it lack batch execution or evaluation metrics?

#### 4. Deliverables for This Phase

```text
Current system capability report
- Supported checks
- Supported languages
- Output format
- Current limitations
- Required changes
```

### Phase 2: Benchmark Dataset Design

The goal is to assemble a diverse collection of repositories to evaluate the system.

Repositories will be categorized into 3 distinct groups:

Group 1: Intentional Vulnerability / Benchmark Repositories

Used to measure the system's detection capabilities.

Recommendations:

- OWASP BenchmarkJava
- WebGoat
- Juice Shop
- NodeGoat
- DVWA
- crAPI
- VAmPI
- WrongSecrets
- RailsGoat
- Kubernetes Goat

Group 2: Clean Real-World Repositories

Used to measure false positive rates and runtime performance.

Recommendations:

- Spring PetClinic
- Express
- Django
- Flask
- RealWorld

Group 3: DevSecOps / IaC / Security Tooling Repositories

Used if the system validates pipelines, Dockerfiles, IaC, or Kubernetes manifests.

Recommendations:

- Trivy
- Checkov
- Semgrep Rules

For each repository, the following metadata must be maintained:

```yaml
name: juice-shop
url: https://github.com/juice-shop/juice-shop
commit: <fixed_commit_hash>
language: typescript
category: vulnerable_app
expected_result: ground-truth/juice-shop.csv
enabled_checks:
  - sast
  - dependency
  - secret
```

Deliverables:

```text
repos.yaml
ground-truth/
  benchmark-java.csv
  juice-shop.csv
  dvwa.csv
  wrongsecrets.csv
```

### Phase 3: System Output Standardization

Before running benchmarks across dozens of repositories, the scan results must be normalized into a unified schema:

Should use a common schema:

```json
{
  "repo": "juice-shop",
  "tool": "security-system",
  "rule_id": "sql-injection",
  "category": "sast",
  "cwe": "CWE-89",
  "severity": "high",
  "file": "routes/search.ts",
  "line": 42,
  "message": "Possible SQL injection",
  "confidence": "medium"
}
```

If the current system lacks JSON/SARIF export capabilities, a custom output converter must be developed.

Objectives:

- Every finding must contain: repo, rule_id, category, severity, file, and line.
- Where applicable, enrich with CWE, OWASP category, and confidence.
- Retain raw outputs for auditing purposes.

Deliverables:

```text
results/raw/<repo>/security-system.*
results/normalized/<repo>.findings.json
```

### Phase 4: Build the Benchmark Runner

The Benchmark Runner is the core automation component responsible for executing the security system across the entire dataset.

Execution Flow:

```text
read repos.yaml -> clone repo -> checkout commit -> run security system -> collect output -> normalize findings -> run baseline tools -> score findings -> generate report
```

Proposed Directory Structure:

```text
benchmark/
  repos.yaml
  runner/
    clone_repo
    run_security_system
    run_baseline_tools
    normalize_results
    score_results
    generate_summary
  ground-truth/
  results/
    raw/
    normalized/
    scored/
    summary.csv
```

The runner must natively support:

- Running a single targeted repository.
- Running the entire dataset.
- Resuming execution if a specific repository scan fails.
- Configurable timeouts per scan.
- Runtime logging.
- Version tracking for the system, ruleset, and baseline tools.

Target CLI Commands:

```bash
benchmark run --repo juice-shop
benchmark run --all
benchmark score --all
benchmark report
```

### Phase 5: Establish Ground Truth

Since different repositories provide different levels of built-in validation data, the scoring strategy must be segmented:

- For OWASP BenchmarkJava: Utilize its native expected results and score findings strictly by test case, CWE, and file.

- For WrongSecrets: Map against their known list of challenges/secrets to evaluate total secrets recovered.

- For Juice Shop, DVWA, WebGoat, crAPI, VAmPI: Curate a representative baseline subset of flaws and manually compile a master reference CSV containing: repo, vuln_id, vulnerability type, CWE, file, line (if applicable), severity, and expected category.

Example Ground Truth CSV:

```csv
repo,vuln_id,type,cwe,file,line,severity
dvwa,DVWA-001,command-injection,CWE-78,vulnerabilities/exec/source/low.php,12,high
juice-shop,JS-001,sql-injection,CWE-89,routes/search.ts,34,high
wrongsecrets,WS-001,hardcoded-secret,CWE-798,src/main/resources/application.properties,8,high
```

- For Production Repositories (Django, Flask, Express): Do not enforce full ground truth. Use them to measure total alert volume and calculate the false positive rate via manual code review.

### Phase 6: Run Baseline Tools

To ensure an objective evaluation, benchmark the system against industry-standard utilities:

| Loại kiểm tra | Baseline tool |
| ------------- | ------------- |
| SAST | Semgrep, CodeQL |
| Secret scanning | Gitleaks, TruffleHog |
| Dependency vulnerability | Trivy, OWASP Dependency-Check |
| Container/IaC/K8s | Trivy, Checkov |

The goal is not to prove our system is "better than everything else," but rather to pinpoint:

- What unique flaws our system catches that baselines miss.
- What flaws our system completely overlooks.
- Whether our system is less or more noisy (false positives).
- Whether our execution speed is viable for CI/CD environments.

### Phase 7: Scoring and Metrics Calculation

For repositories tied to a ground truth dataset:

```text
True Positive (TP): The finding correctly matches an actual vulnerability.
False Positive (FP): The finding is raised but does not exist in the ground truth.
False Negative (FN): An actual vulnerability exists but the system failed to detect it.
```

Metric:

```text
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1-score  = 2 * Precision * Recall / (Precision + Recall)
```

Implement 3 levels of matching strictness:

#### 1. Strict match

- Same CWE.
- Same file.
- Line number matches within a ±5 line threshold.

#### 2. Relaxed match

- Same CWE.
- Same file.
- Line number accuracy ignored.

#### 3. Category match

- Same vulnerability type.
- Used for vulnerable applications lacking deep file/line metadata.

For production repositories, track:

- Findings per KLOC.
- False positive rate (post-manual review).
- Runtime.
- Vulnerability distribution by severity.
- Scan success/failure rate.

### Phase 8: System Weakness Analysis

Once quantitative data is gathered, dissect the bottlenecks across multiple dimensions:

#### 1. By Vulnerability Category

- SQL Injection
- XSS
- Command Injection
- Hardcoded Secret
- Insecure Dependency
- Docker/K8s Misconfiguration

#### 2. By Language

- Java
- JavaScript/TypeScript
- Python
- PHP
- Ruby
- Go

#### 3. By Repository

- Identify which repositories scan perfectly.
- Which repositories fail out entirely.
- Which repositories produce excessive noise.

#### 4. By Severity

- Are critical/high risks being bypassed?
- Is the output flooded with low/info alerts?

Deliverables:

```text
System weakness report
- Missing vulnerability categories
- High false positive rules
- Unsupported languages/stacks
- Slow scan cases
- CI/CD integration issues
```

### Phase 9: System Refinement

Leverage the data from the benchmark report to continuously optimize the engine. Focus on five main pillars:

#### 1. Rule Enrichment

- Author new rules for skipped vulnerability groups.
- Mapping rule clearly to CWE/OWASP Top 10 standards.

#### 2. Noise Mitigation

- Implement rule-based allowlist.
- Inject confidence level parameters.
- Deprecate highly volatile rules.
- Deduplicate dentical findings.

#### 3. Output Optimization

- Native JSON/SARIF export.
- Embed actionable remediation guidance.
- Guarantee exact file/line resolution.

#### 4. Multi-Repo Scalability

- Eradicate hardcoded execution configs.
- Introduce automated tech-stack detection.
- Enforce strict process timeouts/fallbacks.
- Isolate failures so a single crashing repo won't halt the entire suite.

#### 5. CI/CD Optimization

- Enable dependency caching.
- Implement delta scanning (scanning modified files in a Pull Request only).
- Decouple quick scans from full scans.
- Introduce configurable policy gates tied to vulnerability severity.

### Phase 10: Post-Refinement Benchmarking

After completing a cycle of optimization, re-run the benchmark runner using the exact same repository dataset and commit hashes to prove real improvement.

Before/After Comparison Matrix:

| Metric | Pre-Improvement | Post-Improvement |
| ------ | ------------- | ------------ |
| Precision | 0.62 | 0.78 |
| Recall | 0.55 | 0.71 |
| F1-score | 0.58 | 0.74 |
| Avg runtime | 4m20s | 3m10s |
| False positives/repo | 18 | 7 |

Crucial Requirement: The baseline dataset and commit hashes must remain completely identical to ensure the performance gains are genuine and scientifically provable.

### Phase 11: Comprehensive Evaluation Reporting

The final executive report must follow this strict structure:

1. Executive Summary of the initial system.
2. Problem Statement: Why scaling the evaluation scope was necessary.
3. Repository Dataset Composition.
4. Standardized Benchmark Workflow.
5. Baseline Tools Setup.
6. Evaluation Metrics Definitions.
7. Pre-Improvement Baseline Performance.
8. Applied Technical Refinements.
9. Post-Improvement Performance Results.
10. Strengths, Weaknesses, and Comparative Analysis.
11. Conclusion & Future Roadmap.

The conclusion must definitively answer:

- Which vulnerability classes does the system master?
- Where does it lag?
- Is it fast enough for a CI/CD pipeline gate?
- What unique engineering value does it yield compared to commercial open-source baselines?

Final Project Deliverables

Upon completion, the framework will yield:

```text
1. Automated benchmark dataset featuring diverse, multi-stack repositories.
2. Headless automated Benchmark Runner CLI tool.
3. Verified Ground Truth matrices for core applications.
4. Standardized reporting templates (JSON/CSV).
5. Comprehensive metrics dashboard (Precision, Recall, F1, False Positives, Runtime).
6. Objective comparative data matrix against baseline industry tools.
7. Pre/Post-optimization comparative performance logs.
8. Definitive, quantitative evaluation report proving system efficacy.
```

In short, this transformation turns an isolated script into an enterprise-grade security evaluation framework capable of scanning mass repositories, grading them autonomously, and providing mathematical proof of the system's security posture.
