import os
import requests
from dotenv import load_dotenv
from pymongo import MongoClient

# ==============================
# Load Environment Variables
# ==============================
load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
MONGODB_URI = os.getenv("MONGODB_URI")

OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# ==============================
# Validate Configuration
# ==============================
if not OTX_API_KEY:
    raise ValueError(
        "OTX_API_KEY not found in environment variables"
    )

if not MONGODB_URI:
    raise ValueError(
        "MONGODB_URI not found in environment variables"
    )

# ==============================
# OTX Configuration
# ==============================
headers = {
    "X-OTX-API-KEY": OTX_API_KEY
}

# ==============================
# MongoDB Connection
# ==============================
client = MongoClient(MONGODB_URI)

db = client["soc_db"]

iocs = db["iocs"]

# ==============================
# Fetch OTX Threat Intelligence
# ==============================
print("🌐 Fetching AlienVault OTX threat intelligence...")

response = requests.get(
    OTX_URL,
    headers=headers,
    timeout=30
)

print("Status code:", response.status_code)

if response.status_code != 200:
    raise RuntimeError(
        f"Failed to fetch OTX data: HTTP {response.status_code}"
    )

data = response.json()

# ==============================
# Store IOC Data
# ==============================
inserted = 0
skipped = 0

for pulse in data.get("results", []):

    pulse_name = pulse.get("name")
    pulse_created = pulse.get("created")

    for indicator in pulse.get("indicators", []):

        indicator_value = indicator.get("indicator")
        indicator_type = indicator.get("type")

        if not indicator_value:
            continue

        doc = {
            "indicator": indicator_value,
            "type": indicator_type,
            "pulse": pulse_name,
            "created": pulse_created,
            "source": "AlienVault OTX"
        }

        # Avoid duplicate IOC entries
        result = iocs.update_one(
            {
                "indicator": indicator_value,
                "source": "AlienVault OTX"
            },
            {
                "$set": doc
            },
            upsert=True
        )

        if result.upserted_id:
            inserted += 1
        else:
            skipped += 1

print("====================================")
print("✅ OTX ingestion completed")
print(f"📥 New IOCs: {inserted}")
print(f"🔄 Existing IOCs updated: {skipped}")
print("====================================")
