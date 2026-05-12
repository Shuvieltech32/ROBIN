from modules.threat_intel import analyze_services
import json
import os
import time

from modules.services import scan_services

HISTORY_FILE = "data/device_history.json"


def load_history():

    if os.path.exists(HISTORY_FILE):

        with open(HISTORY_FILE, "r") as f:
            return json.load(f)

    return {}


def save_history(history):

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)


def update_history(devices):

    history = load_history()

    for device in devices:

        ip = device.get("ip")

        services = scan_services(ip)
        threats = analyze_services(services)

        if ip not in history:

            history[ip] = {
                "count": 1,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "high_count": 1 if device.get("risk") in ["HIGH", "CRITICAL"] else 0,

                "mac": device.get("mac"),
                "hostname": device.get("hostname"),
                "vendor": device.get("vendor"),
                "risk": device.get("risk"),
                "services": services,
                "threats": threats
            }

        else:

            history[ip]["count"] += 1
            history[ip]["last_seen"] = time.time()

            if device.get("risk") in ["HIGH", "CRITICAL"]:
                history[ip]["high_count"] += 1

                history[ip]["mac"] = device.get("mac")
                history[ip]["hostname"] = device.get("hostname")
                history[ip]["vendor"] = device.get("vendor")
                history[ip]["risk"] = device.get("risk")
                history[ip]["services"] = services
                history[ip]["threats"] = threats

        save_history(history)

    return history

