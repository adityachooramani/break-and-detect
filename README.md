## Break and Detect

This Flask API is intentionally vulnerable. It is packed with SQL injection, broken auth, IDOR, SSRF, hardcoded secrets, and a pinned CVE. None of this is an accident. It is bait. I set it up this way so the scanners in the CI/CD pipeline have something real to catch.

Every time code is pushed, the pipeline kicks off eight security jobs covering secret scanning, SAST, container, IaC, and dynamic live app scans. At the end of the run, a security gate reviews the reports and kills the build if any HIGH or CRITICAL issues make it through.

The repo is built to show a clear before and after. The main branch serves as the vulnerable baseline. The pipeline runs, the gate fails, and the Security tab populates with SARIF findings. Then, the remediation branch is where every finding gets fixed and the pipeline finally goes green.

That before and after state is the entire purpose of the project. It is a practical demonstration of applied AppSec backed by a CI log anyone can audit. The README explains how to run it locally, the Actions tab shows the pipeline in motion, and the Security tab tracks exactly what the scanners caught and how those vulnerabilities were resolved.

## Setup and installation

Prerequisites:

- Python 3.11 or newer (Dockerfile currently uses python:3.13-slim-bookworm)
- pip
- Docker (optional for container run, required for local Trivy/ZAP scans)

Install locally:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 db.py
```

## How to run it locally

Run with Python:

```bash
source .venv/bin/activate
export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 app.py
```

Run with Docker Compose:

```bash
export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
docker compose up --build
```

Quick checks:

```bash
curl -s http://127.0.0.1:5000/health
curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"chintu","password":"chintu123"}'
```

## How the CI/CD security pipeline works

Workflow file: .github/workflows/security.yml

Jobs and what they do:

- GITLEAKS
  - Tool: gitleaks container (ghcr.io/gitleaks/gitleaks:latest)
  - Scan target: repository files for secrets
  - SARIF upload: yes, category gitleaks
  - Exits non-zero only on a real tool crash, not on findings
- BANDIT
  - Tool: Bandit
  - Scan target: Python source code
  - SARIF upload: yes, category bandit
  - Exits non-zero only on a real tool crash, not on findings
- SEMGREP
  - Tool: Semgrep with config p/default
  - Scan target: source code
  - SARIF upload: yes, category semgrep
  - Exits non-zero only on a real tool crash, not on findings
- TRIVY FILESYSTEM
  - Tool: Trivy (ghcr.io/aquasecurity/trivy:0.36.0)
  - Scan target: filesystem and Python dependencies
  - SARIF upload: yes, category trivy-fs
  - Hard-fails the job on HIGH/CRITICAL findings
- TRIVY IMAGE
  - Tool: Trivy (ghcr.io/aquasecurity/trivy:0.36.0)
  - Scan target: built container image
  - SARIF upload: yes, category trivy-image
  - Hard-fails the job on HIGH/CRITICAL findings (see Known gaps below for
    current status of this)
- CHECKOV
  - Tool: Checkov
  - Scan target: dockerfile, github_actions, and terraform frameworks
    (infra/main.tf)
  - SARIF upload: yes, category checkov
  - Reported as advisory in the Security Gate, does not hard-fail
- DYNAMIC
  - Tool: OWASP ZAP baseline via docker run
  - Scan target: running app at http://127.0.0.1:${APP_PORT}
  - Produces zap.json, zap.md, zap.html as artifacts
  - zap.json is converted to SARIF (scripts/zap_to_sarif.py) and uploaded,
    category zap
- SECURITY GATE
  - Tool: inline Python script in the workflow
  - Scan target: downloaded artifacts from all prior jobs
  - Output: consolidated-security-report.md artifact

## How to read the security gate output

- Open the artifact named consolidated-security-report.
- The report table lists each scanner output and its HIGH/CRITICAL count.
- Gitleaks, Bandit, Semgrep, and Trivy filesystem fail the gate on real
  HIGH/CRITICAL findings.
- Checkov is advisory only and does not fail the gate.
- ZAP fails the gate only on high-risk alerts in zap.json.
- Trivy image currently also hard-fails the gate. See Known gaps for the
  current status of this.

## Known gaps or things not yet done

- Trivy image findings: as of 2026-07-09, a local scan against
  python:3.13-slim-bookworm found 21 HIGH/CRITICAL findings, all in Debian 12
  OS packages (examples include perl-base, zlib1g, libsqlite3-0, ncurses, and
  util-linux). None are in Python application dependencies, the filesystem
  scan of requirements.txt is clean. Because the Trivy image job currently
  hard-fails on HIGH/CRITICAL, the Security Gate will fail until one of the
  following is done: switch the base image to a newer tag with fewer
  accumulated OS CVEs, scope Trivy image findings as advisory in the gate
  script the same way Checkov findings are already handled, or both. This
  decision has not yet been applied to the workflow.
- No rate limiting is implemented on any endpoint. This is a known
  application-level gap, not something intentionally toggled between
  branches.
