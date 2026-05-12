import subprocess

def scan_services(ip):
    try:
        result = subprocess.run(
            ["nmap", "-T4", "-F", ip],
            capture_output=True,
            text=True,
            timeout=20
        )

        services = []

        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                services.append(line.strip())

        return services

    except Exception as e:
        print(f"[X] Service scan failed for {ip}: {e}")
        return []

