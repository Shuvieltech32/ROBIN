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
