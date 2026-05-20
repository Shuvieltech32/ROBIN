#!/usr/bin/env python3
from modules.profiler import profile_device
from modules.fingerprint import apply_fingerprints
from modules.device_identity import enrich_devices
from modules.alerts import critical_alert, detect_new_device, critical_threat_alert, service_change_alert
from modules.risk_engine import assign_risk
from modules.firewall import ban_ip
from modules.labels import load_labels
import json
import os
from modules.history import load_history, save_history, update_history
import subprocess
import re
import netifaces
from datetime import datetime
from modules.telegram_alert import send_telegram_alert
import time

BASELINE_FILE = "data/known_devices.json"
LABELS_FILE = "data/labels.json"
HISTORY_FILE = "data/history.json"
LOG_FILE = "logs/robin.log"


def get_default_interface():
    gateways = netifaces.gateways()
    default_gateway = gateways.get("default", {})
    inet_gateway = default_gateway.get(netifaces.AF_INET)

    if not inet_gateway:
        raise RuntimeError("No default IPv4 gateway found.")

    return inet_gateway[1]


def get_cidr_from_interface(interface):
    addrs = netifaces.ifaddresses(interface)
    inet_info = addrs.get(netifaces.AF_INET)

    if not inet_info:
        raise RuntimeError(f"No IPv4 address found on interface {interface}")

    ip = inet_info[0]["addr"]
    netmask = inet_info[0]["netmask"]

    cidr_bits = sum(bin(int(octet)).count("1") for octet in netmask.split("."))
    return f"{ip}/{cidr_bits}"


def run_nmap_scan(target_cidr):
    cmd = ["nmap", "-sn", target_cidr]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout


def parse_nmap_output(output):
    devices = []
    current_ip = None
    current_hostname = None
    current_mac = None
    current_vendor = None

    for line in output.splitlines():
        line = line.strip()

        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            raw_host = host_match.group(1)

            ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", raw_host)
            if ip_match:
                ip = ip_match.group(1)
                hostname = raw_host.split(" (")[0]
            else:
                ip = raw_host
                hostname = None

            current_ip = ip
            current_hostname = hostname
            current_mac = None
            current_vendor = None

            devices.append({
                "ip": current_ip,
                "hostname": current_hostname,
                "mac": current_mac,
                "vendor": current_vendor,
                "label": None,
                "risk": "UNKNOWN"
            })
            continue

        mac_match = re.match(r"MAC Address: ([0-9A-F:]+)(?: \((.+)\))?", line, re.I)
        if mac_match and devices and current_ip:
            devices[-1]["mac"] = mac_match.group(1).upper()
            devices[-1]["vendor"] = mac_match.group(2) if mac_match.group(2) else None

    return devices


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return []

    with open(BASELINE_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return []


def save_baseline(devices):
    with open(BASELINE_FILE, "w") as f:
        json.dump(devices, f, indent=4)


def compare_devices(devices, baseline):
    baseline_ips = {d.get("ip") for d in baseline if d.get("ip")}
    known = []
    new = []

    for d in devices:
        if d.get("ip") in baseline_ips:
            known.append(d)
        else:
            new.append(d)

    return known, new


def color_risk(risk):
    if risk == "HIGH":
        return f"\033[91m{risk}\033[0m"
    if risk == "CRITICAL":
        return f"\033[95m{risk}\033[0m"
    return risk


def log_alert(message):
    timestamp = datetime.now().isoformat(timespec="seconds")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")


def ban_ip(ip):
    print(f"[!] Banning IP: {ip}")
    try:
        subprocess.run([
            "sudo",
            "fail2ban-client",
            "set",
            "sshd",
            "banip",
            ip
        ], check=True)
        print(f"[✓] Successfully banned {ip}")
        log_alert(f"BANNED IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"[X] Failed to ban {ip}")
        log_alert(f"FAILED TO BAN IP: {ip}")


def assign_risk(device, new_devices):

    label = device.get("label")

    trusted_labels = [
        "Home Router",
        "Personal Laptop",
        "ROBIN Server",
        "Family Phone",
        "Smart TV",
        "PlayStation"
    ]

    if device.get("label") in trusted_labels:
        device["status"] = "TRUSTED"
        return "LOW"

    if device in new_devices:
        device["status"] = "INVESTIGATE"
        return "HIGH"

    if device.get("risk") =="CRITICAL":
        device["status"] = "CRITICAL"
        return "CRITICAL"

    device["status"] = "MONITOR"
    return "MEDIUM"

    # trusted devices
    if label in ["Home Router", "Personal Laptop", "ROBIN Server"]:
        return "LOW"

    # suspicious new devices
    if device in new_devices:
        return "HIGH"

    return "MEDIUM"


def correlate_events(devices, known, new, history):
    for device in devices:
        device = profile_device(device)

        ip = device.get("ip")

        if not ip:
            continue

        if device["risk"] == "CRITICAL":

            print(f"[ALERT] {device['ip']} is CRITICAL")

            send_telegram_alert(
                f"   R.O.B.I.N ALERT\n\n"
                f"IP: {device['ip']}\n"
                f"Risk: CRITICAL\n"
                f"Action Recommended: BAN"
            )

            choice = input("Ban this device? (y/n): ")

            if choice.lower() =="y":
                ban_ip(ip)

        record = history.get(ip, {})

        is_new = device in new
        unlabeled = not device.get("label")
        repeated_high = record.get("high_count", 0) >= 2
        repeated_seen = record.get("count", 0) >= 3

        # Event correlation:
        # new + unlabeled + repeated activity = CRITICAL
        if is_new and unlabeled and (repeated_high or repeated_seen):
            device["risk"] = "CRITICAL"

        # known but unlabeled and repeatedly suspicious = HIGH
        elif device in known and unlabeled and repeated_high:
            if device["risk"] != "CRITICAL":
                device["risk"] = "HIGH"

    return devices


def print_report(interface, cidr, devices, known, new):
    print("\n=== R.O.B.I.N. Module 1 Report ===")
    print(f"Time: {datetime.now().isoformat(timespec='seconds')}")
    print(f"Interface: {interface}")
    print(f"Network: {cidr}")
    print(f"Devices found: {len(devices)}")
    print(f"Known devices: {len(known)}")
    print(f"New devices: {len(new)}\n")

    print("All detected devices:")
    for d in devices:
        prefix = "!!" if d.get("risk") in ["HIGH", "CRITICAL"] else "-"
        print(
            f"{prefix} IP: {d.get('ip', 'None'):<15} "
            f"MAC: {str(d.get('mac')):<17} "
            f"Vendor: {str(d.get('vendor')):<20} "
            f"Hostname: {str(d.get('hostname')):<30} "
            f"Label: {str(d.get('label')):<18} "
            f"Type: {d.get('fingerprint', {}).get('device_type', 'Unknown'):<20} "
            f"Confidence: {d.get('fingerprint', {}).get('confidence', 'LOW'):<10} "
            f"Reason: {d.get('fingerprint', {}).get('reason', 'Unknown'):<40} "
            f"Risk: {color_risk(d.get('risk'))}"
        )

    high_risk = [d for d in devices if d.get("risk") == "HIGH"]
    critical_risk = [d for d in devices if d.get("risk") == "CRITICAL"]

    if critical_risk:
        alert_header = "*** CRITICAL ALERT: CRITICAL DEVICES DETECTED ***"
        print(f"\n{alert_header}")
        log_alert(alert_header)

        for d in critical_risk:
            alert_line = (
                f"IP: {d.get('ip')}, MAC: {d.get('mac')}, "
                f"Vendor: {d.get('vendor')}, Hostname: {d.get('hostname')}, "
                f"Label: {d.get('label')}, Risk: {d.get('risk')}"
            )
            print(f" -> {alert_line}")
            log_alert(alert_line)

    elif high_risk:
        warning_header = "*** WARNING: HIGH-RISK DEVICES DETECTED ***"
        print(f"\n{warning_header}")
        log_alert(warning_header)

        for d in high_risk:
            warning_line = (
                f"IP: {d.get('ip')}, MAC: {d.get('mac')}, "
                f"Vendor: {d.get('vendor')}, Hostname: {d.get('hostname')}, "
                f"Label: {d.get('label')}, Risk: {d.get('risk')}"
            )
            print(f" -> {warning_line}")
            log_alert(warning_line)

    else:
        print("\nNo new devices detected.")

    print("\n=== Scan Complete ===")


def main():
    interface = get_default_interface()
    cidr = get_cidr_from_interface(interface)
    scan_output = run_nmap_scan(cidr)
    devices = parse_nmap_output(scan_output)
    devices = enrich_devices(devices)
    devices = apply_fingerprints(devices)

    labels = load_labels()

    print(labels)

    for device in devices:
        ip = device.get("ip")

        print(f"Checking label for IP: {ip}")

        if ip:
            device["label"] = labels.get(ip, "Unknown")
            print(f"Assigned label: {device['label']}")

    baseline = load_baseline()

    if not baseline:
        print("No baseline found. Saving current devices as trusted baseline.")
        save_baseline(devices)
        print("Baseline saved to data/known_devices.json")
        return

    known, new = compare_devices(devices, baseline)

    # Initial risk assignment
    for device in devices:
        device["risk"] = assign_risk(device, new)

        # Unknown devices become HIGH risk
        if device["label"] == "Unknown":
            device["risk"] = "HIGH"

    # Critical threat alerts
    for device in devices:
        critical_threat_alert(device)

    # Load and update history
    history = load_history()
    if history is None:
        history = {}

    for device in devices:
        ip = device.get("ip")
        if ip:
            detect_new_device(ip, history)

    for device in devices:
        ip = device.get("ip")
        services = device.get("services", [])

        if ip:
            service_change_alert(ip, services, history)

    # Event correlation
    devices = correlate_events(devices, known, new, history)

    save_history(history)

    # Manual response for CRITICAL devices
    SAFE_IPS = ["192.168.4.1"]

    for device in devices:
        ip = device.get("ip")
        if not ip:
            continue

        if device["risk"] == "CRITICAL" and ip not in SAFE_IPS:
            print(f"\n[ALERT] {ip} is CRITICAL")

            choice = input("Ban this device? (y/n): ")

            if choice.lower() == "y":
                ban_ip(ip)

    print("[+] Updating device history...")
    update_history(devices)

    print("=== Scan Complete ===")

if __name__ == "__main__":
    while True:
        print("\n=== Starting New Scan Cycle ===\n")

        try:
            scan_main()

        except Exception as e:
            print(f"[ERROR] {e}")

        print("\n=== Scan Complete ===")
        print("waiting 60 seconds before next scan...\n")

        time.sleep(60)
