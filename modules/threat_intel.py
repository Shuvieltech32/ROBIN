import json
import os

CVE_FILE = "data/cve_map.json"


def load_cve_map():
    if os.path.exists(CVE_FILE):
        with open(CVE_FILE, "r") as f:
            return json.load(f)

    return {}


def analyze_services(services):
    cve_map = load_cve_map()

    findings = []

    for service in services:

        try:
            port = service.split("/")[0]

            if port in cve_map:

                findings.append({
                    "port": port,
                    "service": cve_map[port]["service"],
                    "risk": cve_map[port]["risk"],
                    "notes": cve_map[port]["notes"],
                    "recommendation": cve_map[port]["recommendation"]
                })

        except Exception:
            continue

    return findings
