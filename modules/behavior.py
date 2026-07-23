from typing import Any


RISK_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalize_services(services: list[str] | None) -> set[str]:
    """Convert service results into a clean comparable set."""
    if not services:
        return set()

    return {
        service.strip()
        for service in services
        if isinstance(service, str) and service.strip()
    }


def detect_behavior_changes(
    current: dict[str, Any],
    previous: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Compare the current device state with its previous state."""
    events: list[dict[str, str]] = []

    if not previous:
        events.append({
            "type": "NEW_DEVICE",
            "severity": "HIGH",
            "message": "Device was not present in previous history.",
        })
        return events

    fields_to_compare = {
        "hostname": "Hostname",
        "mac": "MAC address",
        "vendor": "Vendor",
        "label": "Device label",
        "profile": "Device profile",
    }

    for field, display_name in fields_to_compare.items():
        old_value = previous.get(field)
        new_value = current.get(field)

        if (
            old_value
            and new_value
            and old_value != new_value
        ):
            events.append({
                "type": f"{field.upper()}_CHANGED",
                "severity": "HIGH",
                "message": (
                    f"{display_name} changed from "
                    f"'{old_value}' to '{new_value}'."
                ),
            })

    old_services = normalize_services(previous.get("services"))
    new_services = normalize_services(current.get("services"))

    for service in sorted(new_services - old_services):
        events.append({
            "type": "SERVICE_OPENED",
            "severity": "HIGH",
            "message": f"New service detected: {service}",
        })

    for service in sorted(old_services - new_services):
        events.append({
            "type": "SERVICE_CLOSED",
            "severity": "LOW",
            "message": f"Service no longer detected: {service}",
        })

    old_risk = str(previous.get("risk", "LOW")).upper()
    new_risk = str(current.get("risk", "LOW")).upper()

    if RISK_LEVELS.get(new_risk, 1) > RISK_LEVELS.get(old_risk, 1):
        events.append({
            "type": "RISK_INCREASED",
            "severity": new_risk,
            "message": f"Risk increased from {old_risk} to {new_risk}.",
        })

    return events

def apply_behavior_risk(
    current_risk: str,
    events: list[dict[str, str]],
) -> tuple[str, str]:
    """Raise risk based on behavior events."""

    risk_order = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    current_risk = str(current_risk).upper()
    event_score = 0
    reasons = []

    for event in events:
        event_type = event.get("type", "")
        severity = event.get("severity", "LOW").upper()

        if event_type == "NEW_DEVICE":
            event_score += 1
            reasons.append("new device")

        elif event_type == "SERVICE_OPENED":
            event_score += 2
            reasons.append("new service opened")

        elif event_type in {
            "HOSTNAME_CHANGED",
            "MAC_CHANGED",
            "VENDOR_CHANGED",
        }:
            event_score += 2
            reasons.append(
                event_type.lower().replace("_", " ")
            )

        elif event_type == "RISK_INCREASED":
            event_score += 2
            reasons.append("risk increased")

        if severity == "CRITICAL":
            event_score += 2

    if event_score >= 5:
        behavior_risk = "CRITICAL"
    elif event_score >= 3:
        behavior_risk = "HIGH"
    elif event_score >= 1:
        behavior_risk = "MEDIUM"
    else:
        behavior_risk = current_risk

    final_risk = max(
        current_risk,
        behavior_risk,
        key=lambda value: risk_order.get(value, 1),
    )

    if reasons:
        reason = (
            "Behavior escalation: " 
            + ", ".join(sorted(set(reasons)))
        )
    else:
        reason = "No behavior-based escalation."

    return final_risk, reason
