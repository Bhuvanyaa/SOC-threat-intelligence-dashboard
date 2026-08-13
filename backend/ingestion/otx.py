import os
import requests
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

# ==============================
# CONFIG
# ==============================
OTX_API_KEY = os.getenv("OTX_API_KEY")
MONGODB_URI = os.getenv("MONGODB_URI")

OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# ==============================
# Validate Configuration
# ==============================
if not OTX_API_KEY:
    raise ValueError("OTX_API_KEY not found in environment variables")

if not MONGODB_URI:
    raise ValueError("MONGODB_URI not found in environment variables")

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
response = requests.get(
    OTX_URL,
    headers=headers,
    timeout=30
)

print("Status code:", response.status_code)
print("Response preview:", response.text[:300])

if response.status_code != 200:
    raise RuntimeError("Failed to fetch OTX data")

data = response.json()

# ==============================
# Store IOC Data
# ==============================
for pulse in data.get("results", []):
    for indicator in pulse.get("indicators", []):
        doc = {
            "indicator": indicator.get("indicator"),
            "type": indicator.get("type"),
            "pulse": pulse.get("name"),
            "created": pulse.get("created"),
            "source": "AlienVault OTX"
        }

        iocs.insert_one(doc)

print("✅ OTX indicators stored successfully")
