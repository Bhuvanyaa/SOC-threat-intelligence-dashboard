# 🛡️ SOC Threat Intelligence Dashboard

A Security Operations Center (SOC) dashboard that integrates threat intelligence, Wazuh security alerts, IOC correlation, and MongoDB to support security event monitoring and threat analysis.

## 🎯 Project Overview

This project collects security alerts from Wazuh, ingests Indicators of Compromise (IOCs) from AlienVault OTX, stores security data in MongoDB, and correlates alerts with known malicious indicators.

The dashboard provides a centralized view of detected threats and their severity.

## ✨ Features

- 📡 Wazuh security alert ingestion
- 🌐 AlienVault OTX threat intelligence integration
- 🔎 IOC-based threat correlation
- 🚨 Threat severity classification
- 📊 Interactive SOC dashboard
- 🗄️ MongoDB-based security data storage
- 🔄 Automatic dashboard refresh
- 🛡️ Environment-variable based secret management

## 🏗️ Architecture

                 ┌─────────────────┐
                 │      Wazuh      │
                 │ Security Alerts │
                 └────────┬────────┘
                          │
                          ▼
                ┌───────────────────┐
                │  Alert Ingestion  │
                │      Python       │
                └─────────┬─────────┘
                          │
                          ▼
                  ┌───────────────┐
                  │    MongoDB    │
                  │   soc_db      │
                  └───────┬───────┘
                          │
             ┌────────────┴────────────┐
             │                         │
             ▼                         ▼
     ┌───────────────┐       ┌────────────────┐
     │ AlienVault OTX│       │ Correlation    │
     │ Threat Intel  │──────▶│ Engine         │
     └───────────────┘       └───────┬────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │ Correlated      │
                            │ Threats         │
                            └────────┬────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │  SOC Dashboard  │
                            │ Dash + Plotly   │
                            └─────────────────┘
                            

## 🛠️ Technologies Used

- Python
- Wazuh
- AlienVault OTX
- MongoDB
- Dash
- Plotly
- Pandas
- Requests
- PyMongo

## 📂 Project Structure

```text
SOC-threat-intelligence-dashboard/
│
├── backend/
│   ├── correlation/
│   └── ingestion/
│
├── config/
│
├── frontend/
│
├── scripts/
│
├── ingest_wazuh_alerts.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
