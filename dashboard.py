from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from modules.auth import (
    change_user_role,
    create_user,
    get_user_by_id,
    list_users,
    set_user_active,
    update_password,
    verify_user,
)
from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from modules.audit import load_audit_log, record_audit_event
import subprocess
from datetime import datetime
from modules.firewall import ban_ip, unban_ip
from modules.analytics import (
    build_incident_analytics,
    build_incident_correlations,
    build_threat_hunting_findings,
    build_security_report,
)
from modules.rbac import role_required
from flask import Flask, render_template, request, Response,  url_for
from dotenv import load_dotenv
from modules.incidents import (
    get_incident,
    load_incidents,
    update_incident_status,
)
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

secret_key = os.getenv("SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "SECRET_KEY is missing. Add it to the .env file."
    )

app.config["SECRET_KEY"] = secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login"
login_manager.login_message = (
    "Please sign in to access the ROBIN dashboard."
)
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_authenticated_user(user_id: str):
    """Reload a user from the session."""

    return get_user_by_id(user_id)

HISTORY_FILE = "data/device_history.json"

def load_device():
    if not os.path.exists(HISTORY_FILE):
        return {}

    with open(HISTORY_FILE, "r") as f:
        return json.load(f)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate a ROBIN user."""

    if current_user.is_authenticated:
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = verify_user(username, password)

        if user is None:
            record_audit_event(
                actor=username or "unknown",
                action="LOGIN_FAILED",
                target=username or "unknown",
                details="Invalid username or password.",
                ip_address=request.remote_addr,
                success=False,
            )

            error = "Invalid username or password."

        else:
            login_user(user)

            record_audit_event(
                actor=user.username,
                action="LOGIN_SUCCESS",
                target=user.username,
                details=f"User logged in with role {user.role}.",
                ip_address=request.remote_addr,
                success=True,
            )

            flash(
                f"Welcome, {user.username}.",
                "success",
            )

            return redirect(url_for("home"))

    return render_template(
        "login.html",
        error=error,
    )

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = current_user.username

    record_audit_event(
        actor=username,
        action="LOGOUT",
        target=username,
        details="User logged out.",
        ip_address=request.remote_addr,
        success=True,
    )

    logout_user()

    return redirect(url_for("login"))

    """End the curren ROBIN seesion."""

    logout_user()

    flash(
        "You have been signed out.",
        "success",
    )

    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    devices = load_device()
    labels = load_labels()

    from modules.profiler import profile_device

    for ip, data in devices.items():
        if isinstance(data, dict):
            data["ip"] = ip
            data["label"] = labels.get(ip, data.get("label", "Unknown"))
            profile_device(data)

    critical_count = sum(
        1 for d in devices.values()
        if isinstance(d, dict) and d.get("risk") == "CRITICAL"
    )

    trusted_count = sum(
        1 for d in devices.values()
        if isinstance(d, dict) and d.get("status") == "TRUSTED"
    )

    return render_template(
        "dashboard.html",
        devices=devices,
        critical_count=critical_count,
        trusted_count=trusted_count
    )

USERNAME = os.getenv("ROBIN_DASH_USER", "admin")
PASSWORD = os.getenv("ROBIN_DASH_PASS", "password")

@app.route("/correlations")
@login_required
def correlation_dashboard():
    """Display related incident groups."""

    correlations = build_incident_correlations()

    return render_template(
        "correlations.html",
        correlations=correlations,
    )

@app.route("/trust/<ip>")
@role_required("ADMIN")
def trust_ip(ip):
    labels = load_labels()

    labels[ip] = "Trusted Device"

    with open("data/labels.json", "w") as f:
        json.dump(labels, f, indent=4)

    return redirect("/")

@app.route("/ignore/<ip>")
@role_required("ADMIN")
def ignore_ip(ip):
    history = load_device()

    if ip in history:
        history[ip]["status"] = "IGNORED"
        history[ip]["risk"] = "LOW"
        history[ip]["reason"] = "Operator ignored this device"

    with open("data/device_history.json", "w") as f:
        json.dump(history, f, indent=4)

    return redirect("/")

@app.route("/ban/<ip>")
@role_required("ADMIN")
def dashboard_ban(ip):
    ban_ip(ip)
    return redirect("/")

def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

@app.route("/")
@login_required
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

@app.route("/investigate/<ip>")
@role_required("ADMIN", "ANALYST")
def investigate(ip):
    devices = load_device()
    labels = load_labels()

    data = devices.get(ip, {})

    if not isinstance(data, dict):
        data = {}

    data["ip"] = ip
    data["label"] = labels.get(ip, data.get("label", "Unknown"))

    from modules.profiler import profile_device
    profile_device(data)

    return render_template("investigate.html", ip=ip, data=data)

@app.route("/scan/<ip>")
@role_required("ADMIN", "ANALYST")
def scan_ip(ip):

    result = subprocess.run(
        ["nmap", "-sV", ip],
        capture_output=True,
        text=True,
        timeout=120
    )

    lines = result.stdout.splitlines()

    clean_lines = []

    for line in lines:

        if "SERVICE FINGERPRINT" in line:
            break

        if "please submit the following fingerprints" in line:
            continue

        if "SF:" in line:
            continue

        clean_lines.append(line)

    output = "\n".join(clean_lines)

    return render_template(
        "scan_result.html",
        ip=ip,
        output=output

    )

@app.route("/ban/<ip>")
@role_required("ADMIN")
def ban(ip):
    ban_ip(ip, method="fail2ban")
    return redirect("/")


@app.route("/unban/<ip>")
@role_required("ADMIN")
def unban(ip):
    unban_ip(ip, method="fail2ban")
    return redirect("/")

@app.route("/incidents")
@role_required("ADMIN", "ANALYST")
def incident_list():
    """Display and filter recorded incidents."""

    incidents = load_incidents()

    search_query = request.args.get("search", "").strip().lower()
    severity_filter = request.args.get("severity", "").strip().upper()
    status_filter = request.args.get("status", "").strip().upper()

    filtered_incidents = []

    for incident in incidents:
        ip_address = str(
            incident.get("ip_address", "")
        ).lower()

        device_label = str(
            incident.get("device_label", "")
        ).lower()

        title = str(
            incident.get("title", "")
        ).lower()

        description = str(
            incident.get("description", "")
        ).lower()

        severity = str(
            incident.get("severity", "")
        ).upper()

        status = str(
            incident.get("status", "")
        ).upper()

        matches_search = (
            not search_query
            or search_query in ip_address
            or search_query in device_label
            or search_query in title
            or search_query in description
        )

        matches_severity = (
            not severity_filter
            or severity == severity_filter
        )

        matches_status = (
            not status_filter
            or status == status_filter
        )

        if (
            matches_search
            and matches_severity
            and matches_status
        ):
            filtered_incidents.append(incident)

    filtered_incidents.sort(
        key=lambda incident: incident.get("created_at", ""),
        reverse=True,
    )

    return render_template(
        "incidents.html",
        incidents=filtered_incidents,
        search_query=search_query,
        severity_filter=severity_filter,
        status_filter=status_filter,
        total_matches=len(filtered_incidents),
    )

@app.route("/incidents/<incident_id>")
@role_required("ADMIN", "ANALYST")
def incident_details(incident_id):
    incident = get_incident(incident_id)

    if incident is None:
        return "Incident not found", 404

    return render_template(
        "incident_details.html",
        incident=incident,
    )


@app.route(
    "/incidents/<incident_id>/status/<new_status>",
    methods=["POST"],
)
@role_required("ADMIN", "ANALYST")
def change_incident_status(incident_id, new_status):
    try:
        updated_incident = update_incident_status(
            incident_id=incident_id,
            new_status=new_status,
            notes="Status changed from the ROBIN dashboard.",
        )
    except ValueError as error:
        return str(error), 400

    if updated_incident is None:
        return "Incident not found", 404

    return redirect(
        url_for(
            "incident_details",
            incident_id=incident_id,
        )
    )

@app.route("/analytics")
@login_required
def analytics_dashboard():
    """Display ROBIN incident analytics."""

    analytics = build_incident_analytics()

    return render_template(
        "analytics.html",
        analytics=analytics,
    )

@app.route("/report")
@login_required
def security_report():
    """Display the ROBIN Phase 7 security report."""

    report = build_security_report()

    return render_template(
        "security_report.html",
        report=report,
    )

@app.route("/hunt")
@login_required
def threat_hunting_dashboard():
    """Display automated threat-hunting findings."""

    findings = build_threat_hunting_findings()

    return render_template(
        "threat_hunting.html",
        findings=findings,
    )

@app.route("/admin/users", methods=["GET", "POST"])
@role_required("ADMIN")
def admin_users():
    message = None
    error = None

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        try:
            if action == "create":
                username = request.form.get("username", "")
                password = request.form.get("password", "")
                role = request.form.get("role", "VIEWER")

                create_user(
                    username=username,
                    password=password,
                    role=role,
                )

                record_audit_event(
                    actor=current_user.username,
                    action="USER_CREATED",
                    target=username.strip().lower(),
                    details=f"Created user with role {role.strip().upper()}.",
                    ip_address=request.remote_addr,
                )

                message = f"User '{username}' created."

            elif action == "disable":
                username = request.form.get("username", "")
                set_user_active(
                    username,
                    False,
                    acting_username=current_user.username,
                )

                record_audit_event(
                    actor=current_user.username,
                    action="USER_DISABLED",
                    target=username.strip().lower(),
                    details="User account disabled.",
                    ip_address=request.remote_addr,
                )

                record_audit_event(
                    actor=current_user.username,
                    action="USER_ENABLED",
                    target=username.strip().lower(),
                    details="User account enabled.",
                    ip_address=request.remote_addr,
                )

                message = f"User '{username}' disabled."

            elif action == "enable":
                username = request.form.get("username", "")
                set_user_active(username, True)
                message = f"User '{username}' enabled."

            elif action == "change_role":
                username = request.form.get("username", "")
                new_role = request.form.get("role", "VIEWER")

                change_user_role(username, new_role)

                record_audit_event(
                    actor=current_user.username,
                    action="USER_ROLE_CHANGE",
                    target=username.strip().lower(),
                    details=f"Role change to {new_role.strip().upper()}.",
                    ip_address=request.remote_addr,
                )

                message = f"Role updated for '{username}'."

            else:
                error = "Unknown admin action."

        except ValueError as exc:
            error = str(exc)

            record_audit_event(
                actor=current_user.username,
                action="ADMIN_ACTION_FAILED",
                target=request.form.get("username", "unknown"),
                details=str(exc),
                ip_address=request.remote_addr,
                success=False,
            )

    return render_template(
        "admin_users.html",
        users=list_users(),
        message=message,
        error=error,
    )

@app.route("/admin/audit")
@role_required("ADMIN")
def admin_audit():
    entries = load_audit_log()

    entries = list(reversed(entries))

    return render_template(
        "audit_log.html",
        entries=entries,
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
