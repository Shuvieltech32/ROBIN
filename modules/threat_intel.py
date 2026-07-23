import json
import os
from typing import Any

CVE_FILE = "data/cve_map.json"


def load_cve_map() -> dict[str, Any]:
    if not os.path.exists(CVE_FILE):
        print(f"[WARNING] CVE map not found: {CVE_FILE}")
        return {}

    try:
        with open(CVE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            print("[WARNING] CVE map must contain a JSON object.")
            return {}

        return data

    except (OSError, json.JSONDecodeError) as error:
        print(f"[ERROR] Could not load CVE map: {error}")
        return {}


def extract_port(service_line: str) -> str | None:
    if not isinstance(service_line, str):
        return None

    first_field = service_line.strip().split()[0]

    if "/" not in first_field:
        return None

    port = first_field.split("/", 1)[0]

    return port if port.isdigit() else None


def analyze_services(services: list[str]) -> list[dict[str, Any]]:
    cve_map = load_cve_map()
    findings: list[dict[str, Any]] = []

    for service_line in services:
        port = extract_port(service_line)

        if not port:
            continue

        intelligence = cve_map.get(port)

        if not isinstance(intelligence, dict):
            continue

        findings.append({
            "port": port,
            "detected_service": service_line,
            "service": intelligence.get("service", "unknown"),
            "risk": intelligence.get("risk", "LOW"),
            "notes": intelligence.get("notes", "No notes available."),
            "recommendation": intelligence.get(
            "recommendation",
            "Investigate the service."
            ),
            "cves": intelligence.get("cves", [])
        })

    return findings
