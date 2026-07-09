# Break and Detect

Break and Detect is a deliberately clean Flask specimen wrapped in a security CI/CD pipeline. The application is the patient; the pipeline is the medicine that watches for the problems we plant later on purpose.

## Architecture

The baseline architecture stays small on purpose: Flask app, SQLite datastore, and layered security controls around the code. The current diagrams live here:

- [App architecture](docs/App_architecture.png)
- [Pipeline architecture](docs/pipeline_architecture.png)

## Run Locally

1. Create and activate a Python 3.11 environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Set `JWT_SECRET` to a strong random value.
4. Initialize the database with `python db.py`.
5. Start the app with `python app.py`.
6. Or run `docker compose up --build` after exporting `JWT_SECRET` in your shell.

## Pipeline

The workflow splits into two lanes and a final gate:

- Static lane: Gitleaks, Bandit, Semgrep, Trivy, and Checkov inspect files and built artifacts without starting the app.
- Dynamic lane: the container is started, health-checked on `/health`, and then OWASP ZAP probes the live HTTP service.
- Gate: a consolidated report is generated from the scan artifacts and fails on missing reports or high/critical findings.

Findings are uploaded to the GitHub Security tab when SARIF is available, and the gate fails on high or critical results.

## Baseline Policy

Deliberate vulnerabilities are planted later on a separate branch or reversible git delta. This repository keeps the clean baseline so the security pipeline starts from a correct reference point.
