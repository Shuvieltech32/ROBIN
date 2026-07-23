import os
import requests
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_telegram_alert(message):

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": message
    }

    try:

        response = requests.post(url, data=payload)

        print("Status:", response.status_code)

        if response.status_code == 200:
            print("[+] Telegram alert sent")

        else:
            print("[!] Telegram failed")

    except Exception as e:

        print(f"[!] Telegram error: {e}")
