"""Analytics functions for ROBIN Phase 7."""

from collections import Counter
from typing import Any, Dict, List

from modules.incidents import load_incidents


def build_incident_analytics() -> Dict[str, Any]:
    """Build summary statistics from ROBIN incident records."""

    incidents: List[Dict[str, Any]] = load_incidents()

    severity_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    device_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    threat_counts: Counter[str] = Counter()

    for incident in incidents:
        severity = str(
            incident.get("severity", "UNKNOWN")
        ).upper()

        status = str(
            incident.get("status", "UNKNOWN")
        ).upper()

        ip_address = str(
            incident.get("ip_address", "Unknown")
        )

        severity_counts[severity] += 1
        status_counts[status] += 1
        device_counts[ip_address] += 1

        evidence = incident.get("evidence", {})

        if not isinstance(evidence, dict):
            evidence = {}

        services = evidence.get("services", [])

        if isinstance(services, list):
            for service in services:
                service_counts[str(service)] += 1

        threats = evidence.get("threats", [])

        if isinstance(threats, list):
            for threat in threats:
                if isinstance(threat, dict):
                    threat_name = (
                        threat.get("name")
                        or threat.get("service")
                        or threat.get("type")
                        or str(threat)
                    )
                else:
                    threat_name = str(threat)

                threat_counts[threat_name] += 1

    active_statuses = {
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
    }

    active_incidents = sum(
        count
        for status, count in status_counts.items()
        if status in active_statuses
    )

    resolved_incidents = status_counts.get("RESOLVED", 0)

    return {
        "total_incidents": len(incidents),
        "active_incidents": active_incidents,
        "resolved_incidents": resolved_incidents,
        "severity_counts": dict(severity_counts),
        "status_counts": dict(status_counts),
        "top_devices": device_counts.most_common(5),
        "top_services": service_counts.most_common(5),
        "top_threats": threat_counts.most_common(5),
    }

def build_incident_correlations() -> List[Dict[str, Any]]:
    """Group related incidents by device and shared evidence."""

    incidents: List[Dict[str, Any]] = load_incidents()

    groups: Dict[str, Dict[str, Any]] = {}

    for incident in incidents:
        ip_address = str(
            incident.get("ip_address", "Unknown")
        )

        evidence = incident.get("evidence", {})

        if not isinstance(evidence, dict):
            evidence = {}

        services = evidence.get("services", [])
        behavior_reason = str(
            evidence.get(
                "behavior_reason",
                "No behavior information",
            )
        )

        if not isinstance(services, list):
            services = []

        group = groups.setdefault(
            ip_address,
            {
                "ip_address": ip_address,
                "device_label": incident.get(
                    "device_label",
                    "Unknown",
                ),
                "incident_count": 0,
                "active_count": 0,
                "critical_count": 0,
                "statuses": Counter(),
                "services": Counter(),
                "behaviors": Counter(),
                "incident_ids": [],
                "first_seen": None,
                "last_seen": None,
            },
        )

        group["incident_count"] += 1
        group["incident_ids"].append(
            incident.get("incident_id")
        )

        status = str(
            incident.get("status", "UNKNOWN")
        ).upper()

        severity = str(
            incident.get("severity", "UNKNOWN")
        ).upper()

        group["statuses"][status] += 1

        if status in {
            "OPEN",
            "INVESTIGATING",
            "CONTAINED",
        }:
            group["active_count"] += 1

        if severity == "CRITICAL":
            group["critical_count"] += 1

        for service in services:
            group["services"][str(service)] += 1

        group["behaviors"][behavior_reason] += 1

        created_at = incident.get("created_at")

        if created_at:
            if (
                group["first_seen"] is None
                or created_at < group["first_seen"]
            ):
                group["first_seen"] = created_at

            if (
                group["last_seen"] is None
                or created_at > group["last_seen"]
            ):
                group["last_seen"] = created_at

    correlations: List[Dict[str, Any]] = []

    for group in groups.values():
        group["statuses"] = dict(group["statuses"])
        group["top_services"] = group["services"].most_common(5)
        group["top_behaviors"] = group["behaviors"].most_common(3)

        del group["services"]
        del group["behaviors"]

        group["correlation_score"] = (
            group["incident_count"] * 2
            + group["critical_count"] * 3
            + group["active_count"]
        )

        correlations.append(group)

    correlations.sort(
        key=lambda item: item.get(
            "correlation_score",
            0,
        ),
        reverse=True,
    )

    return correlations

def build_threat_hunting_findings() -> List[Dict[str, Any]]:
    """Generate threat-hunting findings from correlated incidents."""

    correlations = build_incident_correlations()
    findings: List[Dict[str, Any]] = []

    for group in correlations:
        ip_address = group.get("ip_address", "Unknown")
        device_label = group.get("device_label", "Unknown")

        incident_count = int(
            group.get("incident_count", 0)
        )

        active_count = int(
            group.get("active_count", 0)
        )

        critical_count = int(
            group.get("critical_count", 0)
        )

        correlation_score = int(
            group.get("correlation_score", 0)
        )

        top_services = group.get("top_services", [])
        top_behaviors = group.get("top_behaviors", [])

        if critical_count >= 2:
            findings.append(
                {
                    "severity": "CRITICAL",
                    "category": "Repeated Critical Activity",
                    "ip_address": ip_address,
                    "device_label": device_label,
                    "title": (
                        f"{ip_address} has generated repeated "
                        f"critical incidents"
                    ),
                    "description": (
                        f"This device has generated "
                        f"{critical_count} critical incidents."
                    ),
                    "recommendation": (
                        "Investigate the device immediately, "
                        "review its exposed services, and consider "
                        "isolating it from the network."
                    ),
                    "score": correlation_score + 5,
                }
            )

        if active_count >= 2:
            findings.append(
                {
                    "severity": "HIGH",
                    "category": "Multiple Active Incidents",
                    "ip_address": ip_address,
                    "device_label": device_label,
                    "title": (
                        f"{ip_address} has multiple active incidents"
                    ),
                    "description": (
                        f"There are currently {active_count} active "
                        f"incidents associated with this device."
                    ),
                    "recommendation": (
                        "Review the active incidents together and "
                        "determine whether they are part of the same event."
                    ),
                    "score": correlation_score + 3,
                }
            )

        if incident_count >= 3:
            findings.append(
                {
                    "severity": "HIGH",
                    "category": "Recurring Device Activity",
                    "ip_address": ip_address,
                    "device_label": device_label,
                    "title": (
                        f"{ip_address} repeatedly appears in incidents"
                    ),
                    "description": (
                        f"This device appears in {incident_count} "
                        f"recorded incidents."
                    ),
                    "recommendation": (
                        "Review the device history, validate ownership, "
                        "and determine why it repeatedly triggers alerts."
                    ),
                    "score": correlation_score + 2,
                }
            )

        for service, count in top_services:
            if count < 2:
                continue

            findings.append(
                {
                    "severity": "MEDIUM",
                    "category": "Repeated Service Exposure",
                    "ip_address": ip_address,
                    "device_label": device_label,
                    "title": (
                        f"Repeated service detected on {ip_address}"
                    ),
                    "description": (
                        f"The service '{service}' appeared "
                        f"{count} times across related incidents."
                    ),
                    "recommendation": (
                        "Confirm that the service is required, patched, "
                        "and restricted to trusted devices."
                    ),
                    "score": correlation_score + count,
                }
            )

        for behavior, count in top_behaviors:
            normalized_behavior = str(behavior).lower()

            if (
                count < 2
                or "no behavior" in normalized_behavior
            ):
                continue

            findings.append(
                {
                    "severity": "HIGH",
                    "category": "Repeated Behavior Change",
                    "ip_address": ip_address,
                    "device_label": device_label,
                    "title": (
                        f"Repeated behavior change on {ip_address}"
                    ),
                    "description": (
                        f"The behavior '{behavior}' was observed "
                        f"{count} times."
                    ),
                    "recommendation": (
                        "Compare the device against its baseline and "
                        "investigate whether the change was authorized."
                    ),
                    "score": correlation_score + count + 2,
                }
            )

    findings.sort(
        key=lambda finding: finding.get("score", 0),
        reverse=True,
    )

    return findings

def build_security_report() -> Dict[str, Any]:
    

    analytics = build_incident_analytics()
    correlations = build_incident_correlations()
    findings = build_threat_hunting_findings()

    highest_priority = findings[:5]

    summary_parts = [
        (
            f"ROBIN analyzed "
            f"{analytics.get('total_incidents', 0)} incidents."
        ),
        (
            f"{analytics.get('active_incidents', 0)} incidents are active "
            f"and {analytics.get('resolved_incidents', 0)} are resolved."
        ),
        (
            f"{analytics.get('severity_counts', {}).get('CRITICAL', 0)} "
            f"critical incidents were recorded."
        ),
        (
            f"{len(correlations)} device correlation groups were identified."
        ),
        (
            f"{len(findings)} automated threat-hunting findings "
            f"were generated."
        ),
    ]

    return {
        "summary": " ".join(summary_parts),
        "analytics": analytics,
        "correlations": correlations,
        "findings": findings,
        "highest_priority": highest_priority,
    }
