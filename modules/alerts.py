from modules.telegram_alert import send_telegram_alert


def detect_new_device(ip, history):
    if history[ip]["count"] ==1:
        print(f"[ALERT] NEW DEVICE DETECTED: {ip}")

def critical_alert(device):
    message = (
        f"   R.O.B.I.N ALERT    \n\n"
        f"IP: {device['ip']}\n"
        f"Risk: {device['risk']}\n"
        f"Action Recommended: BAN"
    )

    send_telegram_alert(message)

def detect_new_device(ip, history):
    if ip in history and history[ip].get("count") == 1:
        print(f"[ALERT] NEW DEVICE DETECTED: {ip}")


def critical_threat_alert(device):
    ip = device.get("ip", "Unknown")
    risk = device.get("risk", "LOW")
    label = device.get("label", "Unknown")
    reason = device.get("reason", "No reason provided")

    if risk == "CRITICAL":
        print(f"[CRITICAL ALERT] {ip} | Label: {label} | Reason {reason}")

def service_change_alert(ip, services, history):

    if isinstance(history, dict):
        old_entry = history.get(ip, {})
    else:
        old_entry = {}

    if isinstance(old_entry, dict):
        old_services = old_entry.get("services", [])
    elif isinstance(old_entry, list):
        old_services = old_entry
    else:
        old_services = []

    new_services = []

    for service in services:
        if service not in old_services:
            new_services.append(service)

    for service in new_services:
        print(f"[ALERT] SERVICE CHANGE DETECTED: {ip} opened {service}")

