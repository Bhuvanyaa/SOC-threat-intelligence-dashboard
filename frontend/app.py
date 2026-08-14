import os

import dash
from dash import html, dcc, Input, Output
import plotly.express as px
from pymongo import MongoClient
import pandas as pd
from dotenv import load_dotenv

# ==============================
# Load Environment Variables
# ==============================
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")

if not MONGODB_URI:
    raise ValueError("MONGODB_URI is not configured in the environment.")

# ==============================
# MongoDB Connection
# ==============================
client = MongoClient(MONGODB_URI)

db = client["soc_db"]

wazuh_collection = db["wazuh_alerts"]
ioc_collection = db["iocs"]
correlated_collection = db["correlated_alerts"]


# ==============================
# Fetch Data
# ==============================
def load_wazuh_alerts():
    alerts = list(
        wazuh_collection.find({}, {"_id": 0})
    )
    return pd.DataFrame(alerts)


def load_iocs():
    iocs = list(
        ioc_collection.find({}, {"_id": 0})
    )
    return pd.DataFrame(iocs)


def load_correlated_alerts():
    alerts = list(
        correlated_collection.find({}, {"_id": 0})
    )
    return pd.DataFrame(alerts)


# ==============================
# Dash Application
# ==============================
app = dash.Dash(__name__)

app.title = "SOC Threat Intelligence Dashboard"


# ==============================
# Dashboard Style
# ==============================
CARD_STYLE = {
    "padding": "20px",
    "margin": "10px",
    "backgroundColor": "#f5f5f5",
    "borderRadius": "10px",
    "textAlign": "center",
    "width": "22%",
    "boxShadow": "0 2px 6px rgba(0,0,0,0.15)"
}


# ==============================
# Layout
# ==============================
app.layout = html.Div(
    style={
        "fontFamily": "Arial",
        "padding": "20px",
        "backgroundColor": "#ffffff"
    },

    children=[

        html.H1(
            "🛡️ SOC Threat Intelligence Dashboard",
            style={
                "textAlign": "center",
                "marginBottom": "30px"
            }
        ),

        # ==============================
        # Summary Cards
        # ==============================
        html.Div(
            style={
                "display": "flex",
                "justifyContent": "center",
                "flexWrap": "wrap"
            },

            children=[

                html.Div(
                    [
                        html.H2(id="total-logs"),
                        html.P("Total Wazuh Alerts")
                    ],
                    style=CARD_STYLE
                ),

                html.Div(
                    [
                        html.H2(id="total-iocs"),
                        html.P("Total IOCs")
                    ],
                    style=CARD_STYLE
                ),

                html.Div(
                    [
                        html.H2(id="total-alerts"),
                        html.P("Correlated Threats")
                    ],
                    style=CARD_STYLE
                ),

                html.Div(
                    [
                        html.H2(
                            id="high-severity",
                            style={"color": "#d32f2f"}
                        ),
                        html.P("High Severity")
                    ],
                    style=CARD_STYLE
                )
            ]
        ),

        html.Hr(),

        # ==============================
        # Charts
        # ==============================

        html.Div(
            style={
                "display": "flex",
                "gap": "20px",
                "flexWrap": "wrap"
            },

            children=[

                html.Div(
                    dcc.Graph(id="severity-chart"),
                    style={"flex": "2"}
                ),

                html.Div(
                    dcc.Graph(id="source-chart"),
                    style={"flex": "1"}
                )
            ]
        ),

        html.Hr(),

        # ==============================
        # Recent Alerts
        # ==============================

        html.H3("🚨 Recent Correlated Alerts"),

        html.Div(id="alerts-table"),

        # ==============================
        # Automatic Refresh
        # ==============================

        dcc.Interval(
            id="interval",
            interval=10 * 1000,
            n_intervals=0
        )
    ]
)


# ==============================
# Dashboard Callback
# ==============================
@app.callback(
    [
        Output("total-logs", "children"),
        Output("total-iocs", "children"),
        Output("total-alerts", "children"),
        Output("high-severity", "children"),
        Output("severity-chart", "figure"),
        Output("source-chart", "figure"),
        Output("alerts-table", "children")
    ],

    Input("interval", "n_intervals")
)
def update_dashboard(n):

    # Load database data
    wazuh_df = load_wazuh_alerts()
    ioc_df = load_iocs()
    corr_df = load_correlated_alerts()

    # ==============================
    # Summary
    # ==============================

    total_logs = len(wazuh_df)
    total_iocs = len(ioc_df)
    total_alerts = len(corr_df)

    if not corr_df.empty and "severity" in corr_df.columns:
        high_severity = len(
            corr_df[
                corr_df["severity"].astype(str).str.upper() == "HIGH"
            ]
        )
    else:
        high_severity = 0

    # ==============================
    # Severity Chart
    # ==============================

    if not corr_df.empty and "severity" in corr_df.columns:

        severity_data = (
            corr_df["severity"]
            .astype(str)
            .str.upper()
            .value_counts()
            .reset_index()
        )

        severity_data.columns = ["severity", "count"]

        severity_fig = px.bar(
            severity_data,
            x="severity",
            y="count",
            title="Threats by Severity",
            labels={
                "severity": "Severity",
                "count": "Number of Threats"
            }
        )

    else:

        severity_fig = px.bar(
            title="No Correlated Threats Yet"
        )

    # ==============================
    # IOC Source Chart
    # ==============================

    if not corr_df.empty and "ioc_source" in corr_df.columns:

        source_data = (
            corr_df["ioc_source"]
            .fillna("UNKNOWN")
            .value_counts()
            .reset_index()
        )

        source_data.columns = ["source", "count"]

        source_fig = px.pie(
            source_data,
            names="source",
            values="count",
            hole=0.4,
            title="IOC Source Distribution"
        )

    else:

        source_fig = px.pie(
            names=["No Data"],
            values=[1],
            hole=0.4,
            title="IOC Source Distribution"
        )

    # ==============================
    # Recent Alerts Table
    # ==============================

    if not corr_df.empty:

        recent_df = corr_df.tail(10).iloc[::-1]

        header = html.Tr(
            [
                html.Th("Source IP"),
                html.Th("Description"),
                html.Th("Severity"),
                html.Th("IOC Source"),
                html.Th("Timestamp")
            ]
        )

        rows = []

        for _, row in recent_df.iterrows():

            rows.append(
                html.Tr(
                    [
                        html.Td(row.get("src_ip", "N/A")),
                        html.Td(row.get("description", "N/A")),
                        html.Td(row.get("severity", "N/A")),
                        html.Td(row.get("ioc_source", "N/A")),
                        html.Td(row.get("timestamp", "N/A"))
                    ]
                )
            )

        table = html.Table(
            [header] + rows,
            style={
                "width": "100%",
                "borderCollapse": "collapse",
                "textAlign": "left"
            }
        )

    else:

        table = html.P(
            "No correlated alerts available."
        )

    return (
        total_logs,
        total_iocs,
        total_alerts,
        high_severity,
        severity_fig,
        source_fig,
        table
    )


# ==============================
# Run Application
# ==============================
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8050,
        debug=False
    )
