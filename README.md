# Break and Detect

Break and Detect is a deliberately clean Flask specimen wrapped in a security CI/CD pipeline. The application is the patient; the pipeline is the medicine that watches for the problems we plant later on purpose.

## Architecture

The baseline architecture stays small on purpose: Flask app, SQLite datastore, and layered security controls around the code. The diagram placeholder lives here:

- [docs/architecture.png](docs/architecture.png)

## Run Locally

1. Create and activate a Python 3.11 environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Set `JWT_SECRET` to a strong random value.
4. Initialize the database with `python db.py`.
5. Start the app with `python app.py`.

## Pipeline

The workflow splits into two lanes:

- Static lane: Gitleaks, Bandit, Semgrep, Trivy, and Checkov inspect files and built artifacts without starting the app.
- Dynamic lane: the container is started, health-checked, and then OWASP ZAP probes the live HTTP service.

Findings are uploaded to the GitHub Security tab when SARIF is available, and the gate fails on high or critical results.

## Baseline Policy

Deliberate vulnerabilities are planted later on a separate branch or reversible git delta. This repository keeps the clean baseline, tagged `clean-baseline`, so the security pipeline starts from a correct reference point.
