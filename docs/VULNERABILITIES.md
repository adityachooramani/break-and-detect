# Vulnerability Planting Tracker

This file tracks the deliberate flaws that are added later on a separate branch. The baseline in this repository stays clean.

| Vuln | Endpoint/Location | How it will be planted | Which tool(s) should catch it | Static or Dynamic |
| --- | --- | --- | --- | --- |
| SQL injection | `/search` in `app.py` | Replace the parameterized search query with string concatenation around the `q` parameter. | Bandit, Semgrep, Trivy dependency context, manual review | Static |
| Reflected XSS | `/greet` in `app.py` | Remove HTML escaping and reflect the `name` query parameter directly into the response body. | ZAP baseline, Semgrep rules that flag raw response construction | Dynamic |
| SSRF | `/fetch` in `app.py` | Loosen or remove the URL allowlist/private-network checks so arbitrary URLs can be fetched. | Semgrep, ZAP baseline, manual review | Static and Dynamic |
| Hardcoded secret | JWT signing key in `auth.py` | Swap the environment-backed secret for a literal string in the token issuer/validator. | Gitleaks, Trivy secret scan, Semgrep | Static |
| Known-CVE dependency | `requirements.txt` | Downgrade one pinned package to a version with a published CVE. | Trivy filesystem/image scan | Static |
| Security misconfiguration | `config.yaml` and response headers in `app.py` | Turn `debug` on and strip the hardening headers from the after-request hook. | Checkov, ZAP baseline, Trivy config scanning | Static and Dynamic |
| Runs as root | `Dockerfile` | Reintroduce a root runtime user for the container. | Checkov, Trivy image scan | Static |
| IDOR / BOLA | `/notes/<id>` in `app.py` | Remove the ownership check so callers can read or delete notes they do not own. | Usually missed by automated SAST/DAST; manual authz review and tests are needed | Static and Dynamic |
| Broken auth | `/admin` in `app.py` | Remove or bypass the role check so any authenticated caller can reach the admin endpoint. | Usually missed by automated SAST/DAST; manual auth logic review is needed | Static and Dynamic |

Manual review still matters because IDOR/BOLA and broken-auth bugs are business-rule failures: scanners can probe inputs and patterns, but they cannot reliably infer the intended ownership or role model.
