import os
import time
import requests
import pytest

ZAP_HOST = os.environ.get("ZAP_HOST", "localhost")
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8080"))
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"

def wait_for_zap(timeout=30):
    """Wait until ZAP is reachable or raise an error."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(ZAP_URL, timeout=2)
            if r.status_code == 200:
                return
        except requests.ConnectionError:
            pass
        time.sleep(2)
    raise RuntimeError(f"ZAP did not start within {timeout}s")

@pytest.fixture(scope="module")
def zap_client():
    """Start or connect to ZAP. In CI, the container is already running."""
    # In CI, the container might not be ready immediately, so wait.
    wait_for_zap()
    from zapv2 import ZAPv2
    return ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

def test_security_scan(zap_client):
    """Scan a deliberately vulnerable test site and fail on high/medium alerts."""
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