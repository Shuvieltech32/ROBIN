# R.O.B.I.N

## Real-time Oversight of Breaches, Incidents, & Networks

R.O.B.I.N is a cybersecurity monitoring and threat detection platform designed to identify suspicious devices, exposed services, and potential network threats in real time.

The project focuses on helping usersmonitor local networks, analyze device behavior, classify risks, and improve visibility into cybersecurity threats through automated analysis and reporting.

---

# Features

## Device Discovery
- Detects active devices on the network
- Identifies IP addresses, MAC addresses, hostnames, and vendor
- Tracks known and unknown devices

## Risk Classification
- Labels devices based on threat severity
- Supports LOW, MEDIUM, HIGH< and CRITICAL risk levels
- Tracks recurring susupicious activity

## Threat Intelligence 
- Analyzes exposed ports and services
- Maps ports to security risks using a custom CVE/threat intelligence database
- Provides security recommendations for detected services

## Device History Tracking
- Stores historical scan data
- Tracks first seen and last seen timestamps
- Monitors repeated high-risk detections

## Dashboard Support
- Includes a live monitoring dashboard
- Displays devices, risks, and threat information
- Designed for future real-time visualization improvements

## Future Development
Planned features include:
- Real-time monitoring
- Automated alerting
- Telegram notifications
- Threat scoring improvements
- Auto-blocking using fail2ban/UFW
- Machine learning threat detection
- Advanced reporting and analytics

---

# Technologies Used

- Python 3
- Flask
- Nmap
- Linux / Ubuntu
- Git and GitHub
- JSON-based threat intelligence
- Fail2Ban
- UFW firewall

---

# Installation

Cline the repository:

'''bash
git clone https://github.com/Shuvieltech32/ROBIN.git
cd ROBIN
