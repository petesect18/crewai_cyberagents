import time
from zapv2 import ZAPv2
from .selenium_driver import run_browser_through_zap
from collections import Counter

def perform_zap_scan(target_url):
    print(f"🌐 Target: {target_url}")
    run_browser_through_zap(target_url)

    zap = ZAPv2(
        apikey="myapikey123",
        proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    )

    print(f"✅ Connected to ZAP v{zap.core.version}")

    # 🛠️ Enable aggressive SQLi/XSS scanners
    print("🔧 Enabling aggressive scan rules...")
    zap.ascan.set_option_attack_policy("Default Policy")
    zap.ascan.enable_all_scanners()  # or use enable_scanners with specific IDs

    # Optionally: focus on High-risk plugins (uncomment if needed)
    # high_risk_ids = ["40012", "40014", "40016", "40018"]
    # zap.ascan.enable_scanners(",".join(high_risk_ids))

    # Critical URLs to scan
    attack_urls = [
        f"{target_url}/profile",
        f"{target_url}/profile?xss=<script>alert('reflected')</script>",
        f"{target_url}/contributions?userId=1' OR '1'='1",
        f"{target_url}/allocations/2?userId=2' UNION SELECT NULL--",
        f"{target_url}/memos"
    ]

    for url in attack_urls:
        zap.urlopen(url)
        print(f"📡 Opened: {url}")
        time.sleep(1)

    # 🕷️ Spider
    zap.spider.scan(target_url)
    while int(zap.spider.status()) < 100:
        print(f"🕷️ Spider progress: {zap.spider.status()}%")
        time.sleep(2)

    zap.ajaxSpider.scan(target_url)
    while zap.ajaxSpider.status == 'running':
        print("⚡ AJAX spider running...")
        time.sleep(2)

    # 💣 Active Scan
    for url in attack_urls:
        print(f"💥 Scanning: {url}")
        scan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"⏳ Scan progress for {url}: {zap.ascan.status(scan_id)}%")
            time.sleep(2)

    # 📊 Fetch & report
    alerts = zap.core.alerts(baseurl=target_url)
    print(f"\n📊 ZAP found {len(alerts)} alerts.")
    if not alerts:
        return "⚠️ No vulnerabilities found."

    severity = Counter([a["risk"] for a in alerts])
    for level in ['High', 'Medium', 'Low', 'Informational']:
        print(f"🔎 {level}: {severity.get(level, 0)}")

    report = "\n".join([
        f"""
🛡️ **{a['alert']}**
- **Risk:** {a['risk']}
- **URL:** {a.get('url')}
- **Parameter:** {a.get('param', 'N/A')}
- **Evidence:** {a.get('evidence', 'N/A')}
- **Description:** {a.get('description', 'N/A')}
""" for a in alerts
    ])

    return report
