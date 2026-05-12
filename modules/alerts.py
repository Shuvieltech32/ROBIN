from modules.telegram_alert import send_telegram_alert


def critical_alert(device):
    message = (
        f"   R.O.B.I.N ALERT    \n\n"
        f"IP: {device['ip']}\n"
        f"Risk: {device['risk']}\n"
        f"Action Recommended: BAN"
    )

    send_telegram_alert(message)
