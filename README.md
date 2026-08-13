# 🛡️ SOC Threat Intelligence & Log Correlation Dashboard

A Python-based Security Operations Center (SOC) dashboard that integrates threat intelligence, Wazuh security alerts, MongoDB, and automated alert correlation to identify and visualize potential security threats.

## 🎯 Project Overview

This project demonstrates a SOC monitoring workflow that collects security alerts from Wazuh, ingests Indicators of Compromise (IOCs) from AlienVault OTX, stores security data in MongoDB, and correlates security events with known threat indicators.

The system assigns severity levels to correlated alerts and presents the results through an interactive Plotly Dash dashboard.

## ✨ Key Features

- 🔍 Wazuh security alert ingestion
- 🌐 AlienVault OTX threat intelligence ingestion
- 🧩 IOC-based alert correlation
- 🚨 Automated severity classification
- 🗄️ MongoDB-based security data storage
- 📊 Interactive SOC dashboard
- 🔄 Automatic dashboard refresh
- 🧠 MITRE ATT&CK-based detection rules
- 🔐 Environment-based API key and database configuration

## 🏗️ Architecture

```text
             ┌─────────────────────┐
             │   AlienVault OTX    │
             │  Threat Intelligence│
             └──────────┬──────────┘
                        │
                        ▼
                 ┌─────────────┐
                 │   MongoDB   │
                 │     IOCs    │
                 └──────┬──────┘
                        │
                        │
┌──────────────┐        ▼
│    Wazuh     │──► Correlation Engine
│ Security     │        │
│   Alerts     │        ▼
└──────────────┘  Correlated Alerts
                        │
                        ▼
              ┌──────────────────┐
              │   SOC Dashboard  │
              │   Plotly Dash    │
              └──────────────────┘
