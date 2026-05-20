def profile_device(device):
    ip = device.get("ip", "Unknown")
    services = device.get("services", [])
    label = device.get("label", "Unknown")
    if label == "R.O.B.I.N Server":
        profile = "Security Monitoring Server"

    elif label == "Home Router":
        profile = "Network Router"

    elif label == "Living Room TV":
        profile = "Smart TV"

    elif label == "PlayStation":
        profile = "Gaming Console"

    elif "iPhone" in label:
        profile = "Apple Device"

    elif "Laptop" in label:
        profile = "Personal Computer"

    else:
        profile = "Unknown Device"

        device["profile"] = profile
        return device
    print(f"[DEBUG] Label detected: {label}")

    profile = "Unknown Device"

    if label == "Home Router":
        profile = "Network Router"

    elif label == "Living Room TV":
        profile = "Smart TV"

    elif label == "PlayStation":
        profile = "Gaming Console"

    elif "iPhone" in label:
        profile = "Apple Device"

    elif "Laptop" in label:
        profile = "Personal Computer"

    elif "R.O.B.I.N" in label or "ROBIN" in label:
        profile = "Security Monitoring Server"

    elif 22 in services:
        profile = "Linux/SSH Device"

    elif 80 in services or 443 in services:
        profile = "Web Server"

    elif 3389 in services:
        profile = "Windows RDP Device"

    elif 53 in services:
        profile = "DNS Server"

    elif 445 in services:
        profile = "Windows File Sharing"
 
    device["profile"] = profile

    print(f"[PROFILE] {ip} identified as {profile}")

    return device
