def fingerprint_device(device):
    ip = device.get("ip", "Unknown")
    mac = device.get("mac", "Unknown")
    vendor = device.get("vendor", "Unknown")
    hostname = device.get("hostname", "Unknown")
    label = device.get("label", "Unknown")

    fingerprint = {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "label": label,
        "device_type": "Unknown",
        "confidence": "LOW",
        "reason": "No known fingerprint match found"
    }

    hostname_lower = str(hostname).lower()
    vendor_lower = str(vendor).lower()
    label_lower = str(label).lower()

    if "router" in label_lower or  "gateway" in hostname_lower:
        fingerprint["device_type"] = "Router/Gateway"
        fingerprint["confidence"] = "HIGH"
        fingerprint["reason"] = "Hostname or label match gateway behavior"

    if "sony" in vendor_lower:
        fingerprint["device_type"] = "PlayStation"
        fingerprint["confidence"] = "HIGH"
        fingerprint["reason"] = "Sony vendor detected"

    elif "iphone" in hostname_lower or "apple" in vendor_lower:
        fingerprint["device_type"] = "Apple Device"
        fingerprint["confidence"] = "MEDIUM"
        fingerprint["reason"] = "Apple-related hostname or vendor detected"

    elif "android" in hostname_lower or "samsung" in vendor_lower:
        fingerprint["device_type"] = "Andriod Device"
        fingerprint["confidence"] = "MEDIUM"

    elif "printer" in hostname_lower or "hp" in vendor_lower:
        fingerprint["device_type"] = "Printer"
        fingerprint["confidence"] = "MEDIUM"

    elif "parallels" in hostname_lower or "r.o.b.i.n" in label_lower:
        fingerprint["device_type"] = "R.O.B.I.N Server"
        fingerprint["confidence"] = "HIGH"

    return fingerprint


def apply_fingerprints(devices):
    for device in devices:
        device["fingerprint"] = fingerprint_device(device)

    return devices
