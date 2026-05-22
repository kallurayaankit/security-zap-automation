# Security Test Automation with OWASP ZAP

![CI](https://github.com/kallurayaankit/security-zap-automation/actions/workflows/ci.yml/badge.svg)

Automated security scanning using **OWASP ZAP** integrated with pytest and GitHub Actions.

## Why the badge is red (and why that's good)
The test **intentionally scans a deliberately vulnerable site** (`testphp.vulnweb.com`).  
It **always fails** because that site contains known vulnerabilities.  
This proves the security gate works — it would block such issues from reaching production.

## How it works
- ZAP spiders the target
- Runs an active scan
- Fails the build if high‑ or medium‑risk alerts are found

## Setup (local)

```bash
git clone https://github.com/kallurayaankit/security-zap-automation.git
cd security-zap-automation
python -m venv venv
venv\Scripts\activate.bat   # or source venv/bin/activate
pip install -r requirements.txt
pytest