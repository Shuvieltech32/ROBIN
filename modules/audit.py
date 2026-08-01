import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


AUDIT_FILE = "data/audit_log.json"


def load_audit_log() -> List[Dict[str, Any]]:
    """Load the ROBIN audit log."""

    if not os.path.exists(AUDIT_FILE):
        return []

    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

    except (json.JSONDecodeError, OSError):
        pass

    return []


def save_audit_log(entries: List[Dict[str, Any]]) -> None:
    """Save the ROBIN audit log."""

    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)

    temporary_file = f"{AUDIT_FILE}.tmp"

    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(entries, file, indent=4)

    os.replace(temporary_file, AUDIT_FILE)


def record_audit_event(
    actor: str,
    action: str,
    target: Optional[str] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
    success: bool = True,
) -> Dict[str, Any]:
    """Record one security or administrative event."""

    entries = load_audit_log()

    event = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "actor": actor or "unknown",
        "action": action,
        "target": target,
        "details": details,
        "ip_address": ip_address,
        "success": bool(success),
    }

    entries.append(event)

    # Keep the newest 2,000 events.
    entries = entries[-2000:]

    save_audit_log(entries)

    return event
