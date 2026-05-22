# Security Test Automation with OWASP ZAP

![CI](https://github.com/kallurayaankit/security-zap-automation/actions/workflows/ci.yml/badge.svg)

Automated security scanning using **OWASP ZAP** integrated with pytest and GitHub Actions.

## What it does
- Spiders a target web application
- Runs an active vulnerability scan
- Fails the build if high‑ or medium‑risk alerts are found

## How to run locally
ZAP must be running locally (or use the Docker container).  
The test will wait for ZAP on `localhost:8080`.

```bash
git clone https://github.com/kallurayaankit/security-zap-automation.git
cd security-zap-automation
python -m venv venv
venv\Scripts\activate.bat   # or source venv/bin/activate on Mac/Linux
pip install -r requirements.txt
pytest