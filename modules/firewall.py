import subprocess

def ban_ip(ip, method="iptables"):

    print(f"[!] Banning IP: {ip} using {method}")

    if method == "iptables":

        try:
    
            subprocess.run([
                "sudo",
                "iptables",
                "-A",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP"
            ], check=True)

            print(f"[✓] {ip} blocked with iptables")
            return True

        except subprocess.CalledProcessError as e:

            print(f"[X] iptables ban failed: {e}")
            return False


    elif method == "fail2ban":

        try:

            subprocess.run([
                "sudo",
                "fail2ban-client",
                "set",
                "sshd",
                "banip",
                ip
            ], check=True)

            print(f"[✓] {ip} added to Fail2Ban jail")
            return True

        except subprocess.CalledProcessError as e:

            print(f"[X] fail2ban ban failed: {e}")
            return False


    else:

        print("[X] Unknown ban method")
        return False

def unban_ip(ip, method="iptables"):

    print(f"[+] Unbanning IP: {ip} using {method}")

    if method == "iptables":
        try:
            subprocess.run([
                "sudo",
                "iptables",
                "-D",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP"
            ], check=True)

            print(f"[✓] {ip} removed from iptables")
            return True

        except subprocess.CalledProcessError as e:
            print(f"[X] iptables unban failed: {e}")
            return False

    elif method == "fail2ban":
        try:
            subprocess.run([
                "sudo",
                "fail2ban-client",
                "set",
                "sshd",
                "unbanip",
                ip
            ], check=True)

            print(f"[✓] {ip} removed from Fail2Ban jail")
            return True

        except subprocess.CalledProcessError as e:
            print(f"[X] Fail2Ban unban failed: {e}")
            return False

    else:
        print("[X] Unknown unban method")
        return False

def list_bans():
    subprocess.run([
        "sudo",
        "iptables",
        "-L",
        "INPUT",
        "-v",
        "-n"
    ])
