import socket
import subprocess
import re


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


def get_mac(ip):
    try:
        output = subprocess.check_output(
            ["arp", "-n", ip],
            text=True
        )

        match = re.search(r"(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})", output)

        if match:
            return match.group(0)

    except:
        pass

    return "Unknown"


def get_vendor(mac):
    if mac.startswith("00:1A:79"):
        return "Apple"

    if mac.startswith("B8:27:EB"):
        return "Raspberry Pi"

    if mac == "Unknown":
        return "Unknown"

    return "Generic Device"


def enrich_devices(devices):

    for device in devices:

        ip = device.get("ip")

        if not ip:
            continue

        hostname = get_hostname(ip)
        mac = get_mac(ip)
        vendor = get_vendor(mac)

        device["hostname"] = hostname
        device["mac"] = mac
        device["vendor"] = vendor

    return devices
