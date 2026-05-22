import os
import time
import requests
import pytest

# These environment variables will be set in CI.
# Locally they won't exist, so we skip the real scan.
ZAP_HOST = os.environ.get("ZAP_HOST", "localhost")
ZAP_PORT = os.environ.get("ZAP_PORT", "8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"
CI_RUN = os.environ.get("CI") == "true"  # GitHub Actions sets CI=true

def zap_available():
    """Check if a ZAP instance is reachable."""
    try:
        r = requests.get(ZAP_URL, timeout=2)
        return r.status_code == 200
    except requests.ConnectionError:
        return False

@pytest.fixture(scope="module")
def zap_client():
    """Provide a ZAPv2 client if ZAP is available, else skip all dependent tests."""
    if not zap_available():
        pytest.skip("ZAP is not available. Install and start ZAP locally or run in CI.")
    from zapv2 import ZAPv2
    return ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

def test_security_scan(zap_client):
    """Run an active scan against a vulnerable test site.
    The test fails if high/medium risk alerts are found."""
    target = "http://testphp.vulnweb.com"

    # Spider
    spider_id = zap_client.spider.scan(target)
    while int(zap_client.spider.status(spider_id)) < 100:
        time.sleep(1)

    # Active scan
    scan_id = zap_client.ascan.scan(target)
    while int(zap_client.ascan.status(scan_id)) < 100:
        time.sleep(2)

    # Get alerts
    alerts = zap_client.core.alerts(baseurl=target)
    high_medium = [a for a in alerts if a["risk"] in ("High", "Medium")]

    if high_medium:
        os.makedirs("reports", exist_ok=True)
        with open("reports/alerts.json", "w") as f:
            import json
            json.dump(high_medium, f, indent=2)
        pytest.fail(f"Found {len(high_medium)} high/medium risk alerts. See reports/alerts.json")