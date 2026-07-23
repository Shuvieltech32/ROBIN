import ipaddress

def validate_ip(ip)
    try:
        return str(ipaddress.ip_address(ip)
    except ValueError:
        return None
