import re
from collections import defaultdict

def detect_threats(logs):
    alerts = []
    ip_attempts = defaultdict(int)

    for line in logs:
        try:
            ip = line.split(" ")[0]  # get IP from log
            if re.search(r'(<script>|%3Cscript)', line, re.IGNORECASE):
                alerts.append(("XSS Attempt", ip, line.strip()))
            if re.search(r'login\?user=.*&pass=wrong', line):
                ip_attempts[ip] += 1
                if ip_attempts[ip] >= 5:
                    alerts.append(("Brute Force (5+ tries)", ip, line.strip()))
        except:
            continue
    return alerts

# Test the parser directly
if __name__ == "__main__":
    with open("/var/log/apache2/access.log") as f:
        logs = f.readlines()
    alerts = detect_threats(logs[-100:])
    for alert in alerts:
        print(alert)
