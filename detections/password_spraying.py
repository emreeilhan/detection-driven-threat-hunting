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
    print(f"[ALERT] Possible Password Spraying detected")
    print(f"        Source IP: {alert['source_ip']}")
    print(f"        Users targeted: {len(alert['users'])}")
    print(f"        Time window: {alert['start']} → {alert['end']}")
