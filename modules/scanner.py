#!/usr/bin/env python3
from modules.risk_engine import calculate_risk
from modules.profiler import profile_device
from modules.fingerprint import apply_fingerprints
from modules.device_identity import enrich_devices
from modules.alerts import critical_alert, detect_new_device, critical_threat_alert, service_change_alert
from modules.risk_engine import assign_risk
from modules.firewall import ban_ip
from modules.labels import load_labels
from modules.behavior import (
    detect_behavior_changes,
    apply_behavior_risk,
)

import json
import time
import os
from modules.history import load_history, save_history, update_history
from modules.threat_intel import analyze_services
import subprocess
import re
import netifaces
from datetime import datetime
from modules.telegram_alert import send_telegram_alert
import time

ALERT_CACHE_FILE = "data/alert_cache.json"
ALERT_COOLDOWN = 300  # 5 minutes
BASELINE_FILE = "data/known_devices.json"
LABELS_FILE = "data/labels.json"
HISTORY_FILE = "data/history.json"
LOG_FILE = "logs/robin.log"

def shoould_alert(ip):
    now = time.time()

    if not os.path.exists(ALERT_CACHE_FILE):
        cache = {}
    else:
        with open(ALERT_CACHE_FILE, "r") as f:
            cache = json.load(f)

    last_alert = cache.get(ip, 0)

    if now - last_alert >= ALERT_COOLDOWN:
        cache[ip] = now
        with open(ALERT_CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=4)
        return True

    return False

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


def scan_device_services(ip):
    """Scan common ports and return Nmap-style service lines."""
    cmd = [
        "nmap",
        "-sV",
        "--version-light",
        "--top-ports",
        "100",
        "-T4",
        ip
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=90
        )
    except subprocess.TimeoutExpired:
        print(f"[WARNING] Service scan timed out for {ip}")
        return []
    except subprocess.CalledProcessError as error:
        print(f"[WARNING] Service scan failed for {ip}: {error}")
        return []

    services = []

    for line in result.stdout.splitlines():
        line = line.strip()

        # Matches lines such as:
        # 80/tcp open http Apache httpd
        parts = line.split()

        if (
            len(parts) >= 3
            and "/" in parts[0]
            and parts[1] == "open"
        ):
            services.append(line)

    return services


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

    if device.get("risk") =="CRITICAL" and device.get("status") != "TRUSTED" and should_alert(ip):
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

        risk, status, reason = calculate_risk(device, history)

        device["risk"] = risk
        device["status"] = status
        device["reason"] = reason

        if device.get("risk") == "CRITICAL" and device.get("status") != "TRUSTED":
            print(f"[ALERT] {ip} is CRITICAL")

            send_telegram_alert(
                f"R.O.B.I.N ALERT\n\nIP: {ip}\nRisk: {device.get('risk')}\nAction Recommended: BAN"
            )

            choice = input("Ban this device? (y/n): ")

            if choice.lower() == "y":
                ban_ip(ip)

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

    print("[+] Running service detection...")

    for device in devices:
        ip = device.get("ip")

        if not ip:
            device["services"] = []
            continue

        print(f"[+] Scanning services on {ip}...")
        device["services"] = scan_device_services(ip)
        print(f"[+] Found services: {device['services']}")

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

    for device in devices:
        ip = device.get("ip")
        if not ip:
            continue

        if ip not in history:
            history[ip] = {}

        previous = history.get(ip, {}).copy()

        history[ip]["reason"] = device.get("reason", "No reason listed")
        history[ip]["status"] = device.get("status", "NORMAL")
        history[ip]["profile"] = device.get("profile", "Unknown Device")
        history[ip]["label"] = device.get("label", "Unknown")
        history[ip]["risk"] = device.get("risk", "LOW")

        print(f"[DEBUG] {ip} services: {device.get('services', [])}")

        services = device.get("services", [])
        threats = analyze_services(services)

        history[ip]["services"] = services
        history[ip]["threats"] = threats

        events = detect_behavior_changes(device, previous)
        history[ip]["behavior_events"] = events

        behavior_risk, behavior_reason = apply_behavior_risk(
            device.get("risk", "LOW"),
            events,
        )

        device["risk"] = behavior_risk
        device["behavior_reason"] = behavior_reason

        history[ip]["risk"] = behavior_risk
        history[ip]["behavior_reason"] = behavior_reason

        if events:
            print(f"[BEHAVIOR] {ip}")

            for event in events:
                print(f"    {event['type']} -> {event['message']}")

        history[ip]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    save_history(history)

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
