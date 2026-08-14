import os
import json
import time
from pymongo import MongoClient
from dotenv import load_dotenv

# ==============================
# Load Environment Variables
# ==============================
load_dotenv()

# ==============================
# Wazuh Alert File
# ==============================
ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"

# ==============================
# MongoDB Connection
# ==============================
MONGODB_URI = os.getenv("MONGODB_URI")

if not MONGODB_URI:
    print("❌ MONGODB_URI not found in environment")
    exit(1)

client = MongoClient(MONGODB_URI)

db = client["soc_db"]
collection = db["wazuh_alerts"]

# ==============================
# Start Ingestion
# ==============================
print("📡 Listening for Wazuh alerts...")

with open(ALERT_FILE, "r") as f:
    f.seek(0, 2)

    while True:
        line = f.readline()

        if not line:
            time.sleep(1)
            continue

        try:
            alert = json.loads(line)

            doc = {
                "timestamp": alert.get("timestamp"),
                "rule_id": alert.get("rule", {}).get("id"),
                "description": alert.get("rule", {}).get("description"),
                "level": alert.get("rule", {}).get("level"),
                "src_ip": alert.get("data", {}).get("srcip"),
                "mitre": alert.get("rule", {}).get("mitre", {}),
                "raw": alert
            }

            collection.insert_one(doc)

            print("✔ Stored:", doc["description"])

        except Exception as e:
            print("⚠️ Error:", e)
