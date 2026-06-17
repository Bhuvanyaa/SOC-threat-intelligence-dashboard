import json
import time
from pymongo import MongoClient

ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"

client = MongoClient("mongodb://localhost:27017/")
db = client["soc_db"]
collection = db["wazuh_alerts"]

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
                "description": alert.get("rule", {}).get("description"),
                "level": alert.get("rule", {}).get("level"),
                "src_ip": alert.get("data", {}).get("srcip"),
                "raw": alert
            }

            collection.insert_one(doc)
            print("✔ Stored:", doc["description"])

        except Exception as e:
            print("⚠️ Error:", e)
