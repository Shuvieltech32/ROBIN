def assign_risk(device, new_devices):
    if device.get("label"):
        return "LOW"

    if device in new_devices:
        return "HIGH"

    return "MEDIUM"
