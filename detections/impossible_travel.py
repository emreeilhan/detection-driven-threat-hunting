import csv
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "data/sample/cloud_iam_signins.csv"
TIME_THRESHOLD = timedelta(minutes=60)

events = []

with open(LOG_FILE, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        row["timestamp"] = datetime.fromisoformat(row["timestamp"].replace("Z", ""))
        events.append(row)

events.sort(key=lambda x: x["timestamp"])

events_by_user = defaultdict(list)
for e in events:
    if e["result"] == "success":
        events_by_user[e["username"]].append(e)

alerts = []

for user, logins in events_by_user.items():
    for i in range(len(logins) - 1):
        first = logins[i]
        second = logins[i + 1]

        time_diff = second["timestamp"] - first["timestamp"]

        if (
            time_diff <= TIME_THRESHOLD
            and first["country"] != second["country"]
        ):
            severity = "MEDIUM"

            if (
                first["asn"] != second["asn"]
                or first["device_id"] != second["device_id"]
            ):
                severity = "HIGH"

            alerts.append({
                "user": user,
                "from": f"{first['country']} ({first['city']})",
                "to": f"{second['country']} ({second['city']})",
                "time_diff": time_diff,
                "severity": severity
            })

for alert in alerts:
    print("[ALERT] Impossible Travel Detected")
    print(f"        User: {alert['user']}")
    print(f"        From: {alert['from']} → To: {alert['to']}")
    print(f"        Time difference: {alert['time_diff']}")
    print(f"        Severity: {alert['severity']}")
