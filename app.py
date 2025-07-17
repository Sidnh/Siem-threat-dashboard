from flask import Flask, render_template
import re

app = Flask(__name__)

def detect_threats(logs):
    alerts = []
    for line in logs:
        if "script" in line.lower():
            alerts.append(("XSS Attempt", line))
        elif re.search(r'login\?user=.*&pass=wrong', line):
            alerts.append(("Brute Force", line))
    return alerts

@app.route("/")
def dashboard():
    try:
        with open("/var/log/apache2/access.log") as f:
            logs = f.readlines()
    except FileNotFoundError:
        # Use a sample log file if the real one isn't present
        with open("logs/access.log") as f:
            logs = f.readlines()

    alerts = detect_threats(logs[-100:])

    xss_count = sum(1 for a in alerts if a[0] == "XSS Attempt")
    brute_count = sum(1 for a in alerts if "Brute Force" in a[0])
    total = len(alerts)

    return render_template("index.html", alerts=alerts,
                           total=total, xss=xss_count, brute=brute_count)

if __name__ == "__main__":
    app.run(debug=True)

with open("threat_log.txt", "a") as f:
    f.write(f"{threat_type}: {line}\n")
