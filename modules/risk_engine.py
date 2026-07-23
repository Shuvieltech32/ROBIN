def assign_risk(device, new_devices):
    if device.get("label"):
        return "LOW"

    if device in new_devices:
        return "HIGH"

    return "MEDIUM"

def calculate_risk(device, history):
    ip = device.get("ip")
    label = device.get("label", "Unknown")
    services = device.get("services", [])
    record = history.get(ip, {})

    high_count = record.get("high_count", 0)
    seen_count = record.get("count", 0)

    trusted_labels = [
        "Home Router",
        "Personal Laptop",
        "ROBIN Server",
        "R.O.B.I.N Server",
        "Dimitri iPhone",
        "Dimitri Iphone",
        "Living Room TV",
        "PlayStation",
        "Security Monitoring Server"
    ]

    score = 0
    reasons = []
    status = "NORMAL"

    if label in trusted_labels:
        print(f"[DEBUG] {ip} matched trusted label")
        return "LOW", "TRUSTED", "Trusted device"

    if label == "Unknown":
        score += 20
        reasons.append("Unknown device")

    if len(services) >= 3:
        score += 15
        reasons.append("Multiple open ports")

    if "5000/tcp open upnp" in str(services):
        score += 30
        reasons.append("UPnP exposed")

    if "49152/tcp open unknown" in str(services):
        score += 20
        reasons.append("Unknown high port")

    if high_count >= 5:
        score += 25
        reasons.append("Repeated risky behavior")

    if seen_count >= 10:
        score += 10
        reasons.append("Frequently seen device")

    # Final risk calculation
    if score >= 20:
        risk = "CRITICAL"
    elif score >= 10:
        risk = "HIGH"
    else:
        risk = "LOW"

    reason = ", ".join(reasons) if reasons else "Trusted or low-risk behavior"

    return risk, status, reason
