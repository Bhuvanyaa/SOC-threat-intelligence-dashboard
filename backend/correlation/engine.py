from pymongo import MongoClient

# ==============================
# MongoDB Connection
# ==============================
client = MongoClient("mongodb://localhost:27017/")
db = client["soc_db"]

wazuh_collection = db["wazuh_alerts"]
ioc_collection = db["iocs"]
correlated_collection = db["correlated_alerts"]

# ==============================
# Severity Logic
# ==============================
def calculate_severity(alert):
    description = alert.get("description", "").lower()

    high_patterns = [
        "attempt to login using a non-existent user",
        "invalid user",
        "authentication failure",
        "brute force",
        "password guessing",
        "pam 2 more authentication failures"
    ]

    for pattern in high_patterns:
        if pattern in description:
            return "HIGH"

    if "sudo" in description:
        return "MEDIUM"

    return "LOW"

# ==============================
# Start Correlation
# ==============================
print("🔗 Starting correlation engine...")

# Load IOC IPs
ioc_ips = list(ioc_collection.find({"type": "IPv4"}))
ioc_set = {ioc["indicator"]: ioc for ioc in ioc_ips}

print(f"📌 Loaded {len(ioc_set)} IOC IPs")

# Fetch Wazuh alerts
wazuh_alerts = wazuh_collection.find()

threat_count = 0

for alert in wazuh_alerts:
    src_ip = alert.get("src_ip")

    if not src_ip:
        continue

    if src_ip in ioc_set:
        ioc = ioc_set[src_ip]

        severity = calculate_severity(alert)

        correlated_alert = {
            "src_ip": src_ip,
            "description": alert.get("description"),
            "severity": severity,
            "timestamp": alert.get("timestamp"),
            "rule_id": alert.get("rule_id"),
            "mitre": alert.get("mitre", []),
            "ioc_source": ioc.get("source", "UNKNOWN")
        }

        correlated_collection.insert_one(correlated_alert)
        threat_count += 1

        print(f"🚨 {severity} threat detected from {src_ip}")

print(f"✅ Correlation complete — {threat_count} threats detected")
