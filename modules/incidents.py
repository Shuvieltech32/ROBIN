import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


INCIDENTS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "incidents.json",
)


def _ensure_incident_file() -> None:
    """Create the incidents file if it does not exist."""

    os.makedirs(os.path.dirname(INCIDENTS_FILE), exist_ok=True)

    if not os.path.exists(INCIDENTS_FILE):
        with open(INCIDENTS_FILE, "w", encoding="utf-8") as file:
            json.dump([], file, indent=4)


def load_incidents() -> List[Dict[str, Any]]:
    """Load all saved incidents."""

    _ensure_incident_file()

    try:
        with open(INCIDENTS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        return []

    except (json.JSONDecodeError, OSError):
        return []


def save_incidents(incidents: List[Dict[str, Any]]) -> None:
    """Save incidents to the JSON file."""

    _ensure_incident_file()

    with open(INCIDENTS_FILE, "w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=4)

def find_open_incident(
    ip_address: str,
    title: str,
) -> Optional[Dict[str, Any]]:
    """Return an unresolved incident for the same IP and title."""

    unresolved_statuses = {
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
    }

    for incident in load_incidents():
        same_ip = incident.get("ip_address") == ip_address
        same_title = incident.get("title") == title
        unresolved = incident.get("status") in unresolved_statuses

        if same_ip and same_title and unresolved:
            return incident

    return None

def create_incident(
    ip_address: str,
    severity: str,
    title: str,
    description: str,
    source: str = "ROBIN Detection Engine",
    device_label: str = "Unknown",
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create and save a new incident."""

    incidents = load_incidents()
    timestamp = datetime.now().isoformat(timespec="seconds")

    existing_incident = find_open_incident(
        ip_address=ip_address,
        title=title,
    )

    if existing_incident:
        for incident in incidents:
            if (
                incident.get("incident_id") 
                != existing_incident.get("incident_id")
            ):
                continue

            if evidence:
                current_evidence = incident.setdefault("evidence", {})
                current_evidence.update(evidence)

            incident["description"] = description
            incident["severity"] = severity.upper()
            incident["device_label"] = device_label
            incident["updated_at"] = timestamp

            incident.setdefault("timeline", []).append(
                {
                    "timestamp": timestamp,
                    "action": "Incident evidence updated",
                    "details": (
                        "New evidence collected during a later scan."
                    ),
                }
            )

            save_incidents(incidents)

            print(
                f"[INCIDENT] Existing incident updated for "
                f"{ip_address}: {incident['incident_id']}"
            )

            return incident

    incident = {
        "incident_id": str(uuid.uuid4()),
        "title": title,
        "description": description,
        "severity": severity.upper(),
        "status": "OPEN",
        "source": source,
        "ip_address": ip_address,
        "device_label": device_label,
        "created_at": timestamp,
        "updated_at": timestamp,
        "evidence": evidence or {},
        "timeline": [
            {
                "timestamp": timestamp,
                "action": "Incident created",
                "details": description,
            }
        ],
    }

    incidents.append(incident)
    save_incidents(incidents)

    print(
        f"[INCIDENT] Created {incident['severity']} incident "
        f"{incident['incident_id']} for {ip_address}"
    )

    return incident


def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """Return one incident by its incident ID."""

    for incident in load_incidents():
        if incident.get("incident_id") == incident_id:
            return incident

    return None


def update_incident_status(
    incident_id: str,
    new_status: str,
    notes: str = "",
) -> Optional[Dict[str, Any]]:
    """Update an incident's status and timeline."""

    valid_statuses = {
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
    }

    normalized_status = new_status.upper()

    if normalized_status not in valid_statuses:
        raise ValueError(
            f"Invalid incident status: {new_status}. "
            f"Choose from {sorted(valid_statuses)}."
        )

    incidents = load_incidents()
    timestamp = datetime.now().isoformat(timespec="seconds")

    for incident in incidents:
        if incident.get("incident_id") != incident_id:
            continue

        previous_status = incident.get("status", "OPEN")
        incident["status"] = normalized_status
        incident["updated_at"] = timestamp

        incident.setdefault("timeline", []).append(
            {
                "timestamp": timestamp,
                "action": f"Status changed from {previous_status} "
                f"to {normalized_status}",
                "details": notes,
            }
        )

        save_incidents(incidents)
        return incident

    return None
