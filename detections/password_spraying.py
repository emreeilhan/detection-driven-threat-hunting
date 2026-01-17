import csv
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "data/sample/auth_logs.csv"
TIME_WINDOW = timedelta(minutes=2)
USER_THRESHOLD = 5

events = []

with open(LOG_FILE, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        row["timestamp"] = datetime.fromisoformat(
            row["timestamp"].replace("Z", "")
        )
        events.append(row)

events.sort(key=lambda x: x["timestamp"])

failed_by_ip = defaultdict(list)

for event in events:
    if event["result"] == "failure" and not event["username"].startswith("svc_"):
        failed_by_ip[event["source_ip"]].append(event)

alerts = []

for ip, attempts in failed_by_ip.items():
    attempts.sort(key=lambda x: x["timestamp"])

    for i in range(len(attempts)):
        window_start = attempts[i]["timestamp"]
        window_end = window_start + TIME_WINDOW

        users = set()

        for attempt in attempts[i:]:
            if attempt["timestamp"] <= window_end:
                users.add(attempt["username"])

        if len(users) >= USER_THRESHOLD:
            alerts.append({
                "source_ip": ip,
                "users": users,
                "start": window_start,
                "end": window_end
            })
            break
for alert in alerts:
    ip = alert["source_ip"]
    end_time = alert["end"]

    success_found = False
    compromised_user = None

    for event in events:
        if (
            event["source_ip"] == ip
            and event["result"] == "success"
            and end_time <= event["timestamp"] <= end_time + timedelta(minutes=5)
            and event["username"] in alert["users"]   # 🔑 KRİTİK
        ):
            success_found = True
            compromised_user = event["username"]
            break

    severity = "HIGH" if success_found else "MEDIUM"

    print(f"[ALERT] Password Spraying Detected")
    print(f"        Source IP: {ip}")
    print(f"        Users targeted: {len(alert['users'])}")
    print(f"        Severity: {severity}")

    if success_found:
        print(f"        Compromised account: {compromised_user}")
