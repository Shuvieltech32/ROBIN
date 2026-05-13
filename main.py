from modules.scanner import main as scan_main
from modules.alerts import detect_new_device
import time

def run():
    print("=== R.O.B.I.N Starting ===")
    scan_main()
    print("=== Scan Complete ===")

if __name__ == "__main__":
    while True:
        print("\n=== Starting New Scan Cycle ===\n")

        try:
           scan_main()

        except Exception as e:
            print(f"[ERROR] {e}")

        print("\n=== Scan Complete ==")
        print("waiting 60 seconds before next scan...\n")

        time.sleep(60)
