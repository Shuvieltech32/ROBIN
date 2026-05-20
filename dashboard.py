from datetime import datetime
from modules.firewall import ban_ip, unban_ip
from flask import Flask, render_template, request, Response
from dotenv import load_dotenv
import json
import os
LABELS_FILE = "data/labels.json"

def load_labels():
    if not os.path.exists(LABELS_FILE):
        return {}

    with open(LABELS_FILE, "r") as f:
        return json.load(f)

load_dotenv()

app = Flask(__name__)

HISTORY_FILE = "data/device_history.json"

def load_device():
    if not os.path.exists(HISTORY_FILE):
        return {}

    with open(HISTORY_FILE, "r") as f:
        return json.load(f)

@app.route("/")
def dashboard():
    devices = load_device()
    labels = load_labels()

    from modules.profiler import profile_device

    for ip, data in devices.items():
        if isinstance(data, dict):
            data["ip"] = ip
            data["label"] = labels.get(ip, data.get("label", "Unknown"))
            profile_device(data)

    return render_template("dashboard.html", devices=devices)

USERNAME = os.getenv("ROBIN_DASH_USER", "admin")
PASSWORD = os.getenv("ROBIN_DASH_PASS", "password")


def check_auth(username, password):
    return username == USERNAME and password == PASSWORD


def login_required():
    return Response(
        "Login Required",
        401,
        {"WWW-Authenticate": 'Basic realm="R.O.B.I.N Dashboard"'}
    )


@app.before_request
def require_login():
    auth = request.authorization
    if not auth or not check_auth(auth.username, auth.password):
        return login_required()


@app.route("/")
def home():
    history_file = "data/device_history.json"

    if os.path.exists(history_file):
        with open(history_file, "r") as f:
            history = json.load(f)
    else:
        history = {}

    total_devices = len(history)
    high_risk_total = sum(1 for d in history.values() if d.get("high_count", 0) > 0)
    critical_total = sum(1 for d in history.values() if d.get("high_count", 0) >= 3)

    rows = ""

    for ip, data in history.items():
        label = data.get("label", "Unknown")
        risk = data.get("risk", "LOW")
        status = data.get("status", "MONITOR")
        count = data.get("seen_count", data.get("count", 0))
        high_count = data.get("high_count", 0)

        if risk == "CRITICAL":
            badge_class = "critical"
        elif risk == "HIGH":
            badge_class = "high"
        else:
            badge_class = "low"

        rows += f"""
        <tr>
            <td>{ip}</td>
            <td>{label}</td>
            <td>{data.get("type", data.get("device_type", "Unknown"))}</td>
            <td>{data.get("confidence", "LOW")}</td>
            <td>{count}</td>
            <td>{high_count}</td>
            <td>{datetime.fromtimestamp(data.get("last_seen", 0)).strftime("%Y-%m-%d %H:%M:%S") if data.get("last_seen") else "Unknown"}</td>
            <td>{data.get("reason", "Unknown")}</td>
            <td><span class="badge {badge_class}">{risk}</span></td>
            <td>{status}</td>
            <td>
                <a class="btn danger" href="/ban/{ip}">Ban</a>
                <a class="btn safe" href="/unban/{ip}">Unban</a>
            </td>
        </tr>
        """
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>R.O.B.I.N Dashboard</title>
        <meta http-equiv="refresh" content="10">

        <style>
            body {{
                margin: 0;
                background: #0b1020;
                color: white;
                font-family: Arial, sans-serif;
            }}

            .logo-container {{
                text-align: center;
                padding-top: 20px;
            }}

            .logo {{
                width: 220px;
                height: auto;
            }}

            .main {{
                padding: 30px;
            }}

            .cards {{
                display: flex;
                gap: 20px;
                margin-bottom: 25px;
            }}

            .card {{
                background: #111827;
                padding: 20px;
                border-radius: 12px;
                width: 30%;
                border: 1px solid #334155;
            }}

            .number {{
                font-size: 32px;
                font-weight: bold;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                background: #111827;
            }}

            th, td {{
                padding: 12px;
                border-bottom: 1px solid #334155;
                text-align: left;
            }}

            th {{
                background: #1e293b;
            }}

            .badge {{
                padding: 6px 10px;
                border-radius: 10px;
                font-weight: bold;
            }}

            .low {{ background: green; }}
            .high {{ background: red; }}
            .critical {{ background: purple; }}

            .btn {{
                padding: 7px 10px;
                border-radius: 8px;
                text-decoration: none;
                color: white;
                margin-right: 5px;
            }}

            .danger {{ background: red; }}
            .safe {{ background: royalblue; }}
        </style>
    </head>

    <body>

        <div class="logo-container">
            <img src="/static/robin_logo.png" class="logo">
        </div>

        <div class="main">
            <h1>Security Overview</h1>
            <p>Scanner - Alerts - Response</p>

            <div class="cards">
                <div class="card">
                    <h3>Total Devices</h3>
                    <div class="number">{total_devices}</div>
                </div>

                <div class="card">
                    <h3>High Risk Devices</h3>
                    <div class="number">{high_risk_total}</div>
                </div>

                <div class="card">
                    <h3>Critical Devices</h3>
                    <div class="number">{critical_total}</div>
                </div>
            </div>

            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Label</th>
                    <th>Type</th>
                    <th>Confidence</th>
                    <th>Seen Count</th>
                    <th>High Risk Count</th>
                    <th>Last Seen</th>
                    <th>Reason</th>
                    <th>Risk</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
                {rows}
            </table>

            <p>Auto-refreshes every 10 seconds.</p>
        </div>

    </html>
    """
    return html


@app.route("/ban/<ip>")
def ban(ip):
    ban_ip(ip, method="fail2ban")
    return redirect("/")


@app.route("/unban/<ip>")
def unban(ip):
    unban_ip(ip, method="fail2ban")
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
