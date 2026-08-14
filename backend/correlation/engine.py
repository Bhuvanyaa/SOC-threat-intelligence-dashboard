import os
from pymongo import MongoClient
from dotenv import load_dotenv

# ==============================
# Load Environment Variables
# ==============================
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")

if not MONGODB_URI:
    raise ValueError("MONGODB_URI is not configured.")

# ==============================
# MongoDB Connection
# ==============================
client = MongoClient(MONGODB_URI)

db = client["soc_db"]

wazuh_collection = db["wazuh_alerts"]
ioc_collection = db["iocs"]
correlated_collection = db["correlated_alerts"]


# ==============================
# Severity Logic
# ==============================
def calculate_severity(alert):

    description = str(
        alert.get("description", "")
    ).lower()

    high_patterns = [
        "brute force",
        "password guessing",
        "authentication failure",
        "invalid user",
        "non-existent user",
        "authentication attempts"
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
print("🔗 Starting SOC correlation engine...")

# Load IOC IP addresses
ioc_documents = list(
    ioc_collection.find(
        {"type": "IPv4"}
    )
)

ioc_set = {
    ioc.get("indicator"): ioc
    for ioc in ioc_documents
    if ioc.get("indicator")
}

print(f"📌 Loaded {len(ioc_set)} IOC IPs")


# ==============================
# Process Wazuh Alerts
# ==============================
wazuh_alerts = wazuh_collection.find()

threat_count = 0

for alert in wazuh_alerts:

    src_ip = alert.get("src_ip")

    if not src_ip:
        continue

    # Check whether source IP exists in IOC database
    if src_ip not in ioc_set:
        continue

    ioc = ioc_set[src_ip]

    severity = calculate_severity(alert)

    correlated_alert = {
        "src_ip": src_ip,
        "description": alert.get(
            "description",
            "Unknown activity"
        ),
        "severity": severity,
        "timestamp": alert.get("timestamp"),
        "rule_id": alert.get("rule_id"),
        "mitre": alert.get("mitre", []),
        "ioc_source": ioc.get(
            "source",
            "AlienVault OTX"
        )
    }

    correlated_collection.insert_one(
        correlated_alert
    )

    threat_count += 1

    print(
        f"🚨 {severity} threat detected "
        f"from {src_ip}"
    )


print(
    f"✅ Correlation complete — "
    f"{threat_count} threats detected"
)
