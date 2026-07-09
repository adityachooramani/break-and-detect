# Break and Detect

## What this project is

This repository contains a Flask API backed by SQLite and a GitHub Actions security workflow. The API handles user registration and login, note CRUD, note search, a guarded fetch endpoint, and an admin endpoint. The workflow runs multiple scanners and produces a consolidated gate report. Everything in this README is based on the current files in this repository.

## Features

- Flask API endpoints currently implemented:
	- GET /health and GET /healthz
	- POST /auth/register
	- POST /auth/login
	- POST /notes
	- GET /notes
	- GET /notes/<int:note_id>
	- DELETE /notes/<int:note_id>
	- GET /search
	- GET /fetch
	- GET /greet
	- GET /admin
- JWT auth middleware via Authorization: Bearer <token>.
- Password hashing with bcrypt.
- SQLite schema creation and seed data in db.py.
- Docker image build and container run support.
- GitHub Actions jobs for static and dynamic security scanning.

Security-related behavior verified in code:

- SQL injection via raw query: not present in app.py. SQL calls are parameterized.
- Weak JWT handling: not obvious in current code. Tokens include exp and are verified with PyJWT. Secret is loaded from JWT_SECRET env var.
- IDOR or BOLA: direct object access checks are present on note read and delete.
- SSRF: fetch endpoint enforces allowed scheme list and blocks private or loopback targets.
- Hardcoded secrets: not present in auth.py.
- Missing rate limiting: no rate limiting implementation found.
- Verbose error output: app debug is controlled by config.yaml and currently set to false.
- Missing security headers: not present. app.py sets X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy.
- Reflected XSS: greet endpoint escapes user input before rendering HTML.

## Tech stack

- Python 3
- Flask
- SQLite
- PyJWT
- bcrypt
- requests
- Docker and Docker Compose
- GitHub Actions

## Project structure

.
├── .dockerignore
├── .github
│   └── workflows
│       └── security.yml
├── Dockerfile
├── README.md
├── app.db
├── app.py
├── auth.py
├── config.yaml
├── db.py
├── docker-compose.yml
├── docs
│   ├── App_architecture.png
│   ├── VULNERABILITIES.md
│   └── pipeline_architecture.png
├── requirements.txt
└── scripts
		└── consolidate_security_reports.py

## Setup and installation

Prerequisites:

- Python 3.11 or newer (Dockerfile currently uses python:3.13-slim-bookworm)
- pip
- Docker (optional for container run)

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
	- SARIF upload in this job: yes (upload-sarif, category gitleaks)
- BANDIT
	- Tool: Bandit
	- Scan target: Python source code
	- SARIF upload in this job: yes (category bandit)
- SEMGREP
	- Tool: Semgrep with config p/default
	- Scan target: source code
	- SARIF upload in this job: yes (category semgrep)
- TRIVY FILESYSTEM
	- Tool: Trivy action
	- Scan target: filesystem and dependencies in workspace
	- SARIF upload in this job: yes (category trivy-fs)
- TRIVY IMAGE
	- Tool: Trivy action
	- Scan target: built container image
	- SARIF upload in this job: yes (category trivy-image)
- CHECKOV
	- Tool: Checkov
	- Scan target: dockerfile and github_actions frameworks (not Terraform)
	- SARIF upload in this job: yes (category checkov)
- DYNAMIC
	- Tool: OWASP ZAP baseline via docker run
	- Scan target: running app at http://127.0.0.1:${APP_PORT}
	- SARIF upload in this job: no
	- Artifact upload in this job: yes (zap.json, zap.md, zap.html in reports dir)
- SECURITY GATE
	- Tool: inline Python script in workflow
	- Scan target: downloaded artifacts from prior jobs
	- SARIF upload in this job: no
	- Output: consolidated-security-report.md artifact

## How to read the security gate output

- Open the artifact named consolidated-security-report.
- The report table lists each scanner output and HIGH or CRITICAL count.
- Gate behavior from current workflow:
	- gitleaks, bandit, semgrep, trivy-fs, trivy-image can fail the gate when SARIF result level is error.
	- Checkov is reported as advisory in the gate script.
	- ZAP can fail the gate only when zap.json contains high risk alerts.

## Known gaps or things not yet done

- Branch layout: only main exists locally and as origin/main. No separate vulnerable branch or remediation branch exists in this repo right now.
- Terraform: no .tf files found.
- Checkov is currently not doing general IaC coverage. It is configured for dockerfile and github_actions frameworks only.
- Dynamic ZAP job does not upload SARIF to GitHub Security tab.
- Several scanner steps still mask failures with || true, and some upload-sarif steps use continue-on-error: true.
- requirements.txt and base image are pinned, but CVE-clean status is unconfirmed without running scanners against current versions.
