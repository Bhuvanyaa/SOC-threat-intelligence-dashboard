import os
import requests
from pymongo import MongoClient

# ==============================
# CONFIG
# ==============================
OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

if not OTX_API_KEY:
    print("❌ OTX_API_KEY not found in environment")
    exit(1)

headers = {
    "X-OTX-API-KEY": OTX_API_KEY
}

import os

client = MongoClient(os.getenv("MONGODB_URI"))
iocs = db.iocs

response = requests.get(OTX_URL, headers=headers, timeout=30)

print("Status code:", response.status_code)
print("Response preview:", response.text[:300])

if response.status_code != 200:
    print("❌ Failed to fetch OTX data")
    exit(1)

data = response.json()

for pulse in data.get("results", []):
    for indicator in pulse.get("indicators", []):
        doc = {
            "indicator": indicator.get("indicator"),
            "type": indicator.get("type"),
            "pulse": pulse.get("name"),
            "created": pulse.get("created")
        }
        iocs.insert_one(doc)

print("✅ OTX indicators stored successfully")
