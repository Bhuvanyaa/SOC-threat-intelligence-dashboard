import os
import dash
from dash import html, dcc
import plotly.express as px
from pymongo import MongoClient
import pandas as pd

# ==============================
# MongoDB Connection
# ==============================
import os

client = MongoClient(os.getenv("MONGODB_URI"))
db = client["soc_db"]

wazuh_collection = db["wazuh_alerts"]
correlated_collection = db["correlated_alerts"]

# ==============================
# Fetch Data
# ==============================
def load_wazuh_alerts():
    alerts = list(wazuh_collection.find({}, {"_id": 0}))
    return pd.DataFrame(alerts)

def load_correlated_alerts():
    alerts = list(correlated_collection.find({}, {"_id": 0}))
    return pd.DataFrame(alerts)

# ==============================
# Dash App
# ==============================
app = dash.Dash(__name__)
app.title = "SOC Dashboard"

# ==============================
# Layout
# ==============================
app.layout = html.Div(
    style={"fontFamily": "Arial", "padding": "20px"},
    children=[

        html.H1("🛡️ SOC Dashboard", style={"textAlign": "center"}),

        html.Hr(),

        # Summary Cards
        html.Div(
            style={"display": "flex", "justifyContent": "space-around"},
            children=[
                html.Div(id="total-alerts"),
                html.Div(id="total-correlated"),
            ]
        ),

        html.Br(),

        # Severity Chart
        dcc.Graph(id="severity-chart"),

        html.Br(),

        html.H3("🚨 Recent Correlated Alerts"),
        html.Div(id="alerts-table"),

        # Auto refresh every 10 seconds
        dcc.Interval(
            id="interval",
            interval=10 * 1000,
            n_intervals=0
        )
    ]
)

# ==============================
# Callbacks
# ==============================
@app.callback(
    [
        dash.Output("total-alerts", "children"),
        dash.Output("total-correlated", "children"),
        dash.Output("severity-chart", "figure"),
        dash.Output("alerts-table", "children")
    ],
    [dash.Input("interval", "n_intervals")]
)
def update_dashboard(n):
    wazuh_df = load_wazuh_alerts()
    corr_df = load_correlated_alerts()

    # Summary
    total_alerts = len(wazuh_df)
    total_corr = len(corr_df)

    total_alerts_div = html.Div([
        html.H2(total_alerts),
        html.P("Total Wazuh Alerts")
    ])

    total_corr_div = html.Div([
        html.H2(total_corr),
        html.P("Correlated Threats")
    ])

    # Severity Chart
    if not corr_df.empty:
        fig = px.histogram(
            corr_df,
            x="severity",
            title="Threat Severity Distribution",
            color="severity"
        )
    else:
        fig = px.histogram(title="No Correlated Alerts Yet")

    # Alerts Table
    if not corr_df.empty:
        table = html.Table(
            [
                html.Tr([
                    html.Th("Time"),
                    html.Th("Source IP"),
                    html.Th("Severity"),
                    html.Th("Description"),
                    html.Th("IOC Source")
                ])
            ] +
            [
                html.Tr([
                    html.Td(row.get("timestamp")),
                    html.Td(row.get("src_ip")),
                    html.Td(row.get("severity")),
                    html.Td(row.get("description")),
                    html.Td(row.get("ioc_source"))
                ]) for _, row in corr_df.tail(10).iterrows()
            ],
            style={"width": "100%", "border": "1px solid black"}
        )
    else:
        table = html.P("No correlated alerts available")

    return total_alerts_div, total_corr_div, fig, table

# ==============================
# Run App
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050, debug=False)
