import csv
import json
import requests
import ipaddress
import os
import time
from datetime import datetime
from dotenv import load_dotenv

# Load API key securely
load_dotenv()
API_KEY = os.getenv("API_KEY")

# Risk scoring
BEHAVIOR_RISK = {
    "High": 50,
    "Medium": 30,
    "Low": 10
}

IP_RISK = {
    "malicious": 50,
    "suspicious": 30,
    "safe": 0
}

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        data = response.json()

        malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

        if malicious > 5:
            return "malicious"
        elif malicious > 0:
            return "suspicious"
        else:
            return "safe"

    except:
        return "safe"

def check_local(ip, db):
    if ip in db["malicious"]:
        return "malicious"
    elif ip in db["suspicious"]:
        return "suspicious"
    return "safe"

def get_ip_status(ip, db):
    local = check_local(ip, db)
    vt = check_virustotal(ip)
    return max(local, vt, key=lambda x: IP_RISK[x])

def parse_time(t):
    return datetime.strptime(t, "%Y-%m-%d %H:%M:%S")

def analyze():
    with open("threat_db.json") as f:
        db = json.load(f)

    user_logs = {}

    with open("logs.csv") as f:
        logs = list(csv.DictReader(f))

    print("="*50)
    print("         MINI SOC PLATFORM REPORT")
    print("="*50)

    results = []

    for log in logs:
        user = log["user"]
        ip = log["ip"]
        loc = log["location"]
        time_val = parse_time(log["timestamp"])

        if user not in user_logs:
            user_logs[user] = []

        alerts = []
        risk_score = 0

        # Behavior detection
        if 0 <= time_val.hour <= 6:
            alerts.append("Odd Hour Login")
            risk_score += BEHAVIOR_RISK["Medium"]

        for prev in user_logs[user]:
            diff = (time_val - prev["time"]).total_seconds() / 60
            if prev["location"] != loc and diff < 30:
                alerts.append("Impossible Travel")
                risk_score += BEHAVIOR_RISK["High"]

        # IP reputation
        if is_valid_ip(ip):
            ip_status = get_ip_status(ip, db)
            risk_score += IP_RISK[ip_status]
        else:
            ip_status = "invalid"

        # Final verdict
        if risk_score >= 80:
            verdict = "CRITICAL 🔴"
        elif risk_score >= 50:
            verdict = "HIGH 🟠"
        elif risk_score >= 20:
            verdict = "MEDIUM 🟡"
        else:
            verdict = "LOW 🟢"

        print(f"\nUser: {user}")
        print(f"IP: {ip} ({ip_status.upper()})")
        print(f"Alerts: {alerts if alerts else 'None'}")
        print(f"Risk Score: {risk_score}")
        print(f"FINAL VERDICT: {verdict}")
        print("-"*50)

        results.append((user, ip, ip_status, risk_score, verdict))

        user_logs[user].append({
            "time": time_val,
            "location": loc
        })

        time.sleep(2)  # API rate safety

    # Save report
    with open("report.txt", "w") as f:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"Report Generated At: {current_time}\n\n")

        for r in results:
            f.write(f"User: {r[0]} | IP: {r[1]} | Status: {r[2]} | Score: {r[3]} | Verdict: {r[4]}\n")

    print("\nReport saved as report.txt\n")

if __name__ == "__main__":
    analyze()