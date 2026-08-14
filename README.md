🛡️ SOC Threat Intelligence & Log Correlation Dashboard

A Python-based Security Operations Center (SOC) dashboard that integrates Wazuh security alerts, AlienVault OTX threat intelligence, IOC correlation, MongoDB, and an interactive Dash dashboard for security monitoring and threat analysis.

🎯 Project Overview

This project demonstrates a practical SOC monitoring workflow for collecting security alerts, ingesting Indicators of Compromise (IOCs), correlating security events with known threat indicators, classifying threat severity, and visualizing security findings through a centralized dashboard.

The system uses Wazuh for security alert generation, AlienVault OTX for threat intelligence, MongoDB for security data storage, and Python-based correlation logic to identify potentially malicious activity.

📸 Dashboard Preview

"SOC Threat Intelligence Dashboard" (screenshots/dashboard.png)

✨ Key Features

- 📡 Wazuh security alert ingestion
- 🌐 AlienVault OTX threat intelligence ingestion
- 🔎 IOC-based alert correlation
- 🚨 Automated threat severity classification
- 🗄️ MongoDB-based security data storage
- 📊 Interactive SOC dashboard
- 📈 Threat severity visualization
- 🔄 Automatic dashboard refresh
- 🛡️ Environment-variable based configuration
- 🧩 Configurable security correlation rules
- 🎯 MITRE ATT&CK mapping support

🏗️ Architecture

                    ┌─────────────────────┐
                    │       Wazuh         │
                    │   Security Alerts   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Alert Ingestion    │
                    │       Python        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      MongoDB        │
                    │    Wazuh Alerts     │
                    └──────────┬──────────┘
                               │
                               │
┌─────────────────────┐        ▼
│   AlienVault OTX    │   ┌─────────────────────┐
│ Threat Intelligence  │──▶│ Correlation Engine │
│       / IOCs         │   └──────────┬──────────┘
└─────────────────────┘              │
          │                          │
          ▼                          ▼
   ┌───────────────┐       ┌─────────────────────┐
   │    MongoDB    │       │ Correlated Threats  │
   │   IOC Data    │       └──────────┬──────────┘
   └───────────────┘                  │
                                      ▼
                           ┌─────────────────────┐
                           │    SOC Dashboard    │
                           │    Dash + Plotly    │
                           └─────────────────────┘

🔄 SOC Workflow

1. Wazuh generates security alerts.
2. The Wazuh ingestion script reads alert events from the Wazuh alert log.
3. Security alerts are stored in MongoDB.
4. AlienVault OTX provides threat intelligence indicators.
5. OTX indicators are stored in the MongoDB IOC collection.
6. The correlation engine compares alert source IP addresses with known IOC IPs.
7. Matching events are assigned a severity level based on configured security-event patterns.
8. Correlated alerts are stored in MongoDB.
9. The Dash dashboard displays alert statistics, severity distribution, and recent correlated threats.

🚨 Threat Detection & Correlation

The correlation engine checks Wazuh alerts against known IPv4 indicators stored in the IOC database.

Security-event patterns are used to classify correlated alerts.

HIGH

Examples include:

- Invalid user authentication attempts
- Authentication failures
- Brute-force activity
- Password guessing
- Multiple authentication failures

MEDIUM

- Sudo-related activity

LOW

- Other correlated events that do not match the configured higher-severity patterns

🧠 MITRE ATT&CK

The project uses configurable correlation rules that support MITRE ATT&CK technique mapping.

The detection configuration includes MITRE ATT&CK references such as:

- T1078 — Valid Accounts

Additional techniques can be added through the project's correlation configuration.

🛠️ Technologies Used

Technology| Purpose
Python| Backend processing, ingestion and correlation
Wazuh| Security event monitoring and alert generation
AlienVault OTX| Threat intelligence and IOC ingestion
MongoDB| Security alert and IOC storage
Plotly Dash| Interactive SOC dashboard
Plotly| Threat visualization
Pandas| Alert data processing
Requests| API communication
PyMongo| MongoDB integration
Python-dotenv| Environment variable management
YAML| Security and application configuration
MITRE ATT&CK| Threat technique mapping

📂 Project Structure

SOC-threat-intelligence-dashboard/
│
├── backend/
│   ├── correlation/
│   │   ├── correlation.yaml
│   │   └── engine.py
│   │
│   └── ingestion/
│       └── otx.py
│
├── config/
│   ├── backend.yaml
│   ├── correlation.yaml
│   ├── threat_intel.yaml
│   └── wazuh.yaml
│
├── frontend/
│   └── dashboard.py
│
├── scripts/
│
├── screenshots/
│   └── dashboard.png
│
├── ingest_wazuh_alerts.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md

«Note: If your actual Dash Python filename is different from "dashboard.py", replace "dashboard.py" above with the actual filename.»

⚙️ Configuration

The project uses environment variables for sensitive configuration.

Create a local ".env" file:

OTX_API_KEY=your_otx_api_key
MONGODB_URI=mongodb://localhost:27017/

Security

The real ".env" file must never be committed to GitHub.

Use ".env.example" as the configuration template:

OTX_API_KEY=
MONGODB_URI=

The ".gitignore" file excludes ".env" from version control.

📦 Installation

1. Clone the repository

git clone https://github.com/Bhuvanyaa/SOC-threat-intelligence-dashboard.git
cd SOC-threat-intelligence-dashboard

2. Create a virtual environment

python -m venv venv

3. Activate the virtual environment

Linux/Kali:

source venv/bin/activate

Windows:

venv\Scripts\activate

4. Install dependencies

pip install -r requirements.txt

5. Configure environment variables

Create a local ".env" file and configure:

OTX_API_KEY=your_otx_api_key
MONGODB_URI=mongodb://localhost:27017/

▶️ Running the Project

1. Start MongoDB

Make sure your MongoDB service is running.

2. Ingest AlienVault OTX threat intelligence

python backend/ingestion/otx.py

This retrieves threat intelligence indicators from AlienVault OTX and stores them in MongoDB.

3. Ingest Wazuh alerts

On the Wazuh system, run:

python ingest_wazuh_alerts.py

The script monitors the Wazuh alert log and stores relevant alert information in MongoDB.

4. Run the correlation engine

python backend/correlation/engine.py

The correlation engine compares Wazuh source IPs against known IOC IPs and stores matching events as correlated alerts.

5. Start the SOC dashboard

Run the Dash application:

python frontend/dashboard.py

Then open:

http://localhost:8050

📊 Dashboard

The SOC dashboard provides a centralized view of security monitoring data, including:

- Total Wazuh alerts
- Correlated threats
- Threat severity distribution
- Recent correlated alerts
- Source IP information
- Alert descriptions
- IOC source information
- Automatically refreshed dashboard data

🔐 Security Considerations

- API keys are loaded through environment variables.
- ".env" is excluded from Git version control.
- ".env.example" contains no real credentials.
- Real API keys must never be committed to the repository.
- MongoDB connection details are configurable through environment variables.
- Exposed credentials should be revoked and rotated immediately.

🚀 Future Improvements

- Add additional threat intelligence sources
- Add AbuseIPDB integration
- Support domain and file-hash IOC correlation
- Add advanced alert filtering and search
- Improve SOC dashboard visual design
- Add authentication and role-based access control
- Add email or messaging-based security notifications
- Expand MITRE ATT&CK correlation rules
- Add Docker deployment
- Add automated testing
- Add CI/CD integration
- Add historical threat analytics

📌 Learning Outcomes

Through this project, I developed practical experience in:

- SOC monitoring concepts
- SIEM alert processing
- Threat intelligence integration
- IOC analysis
- Security event correlation
- Log analysis
- MongoDB-based security data storage
- Python security automation
- Security dashboard development
- MITRE ATT&CK-based detection concepts

👩‍💻 Author

Bhuvanyaa S

Cybersecurity Graduate | SOC | SIEM | VAPT | Network Security
