import csv
from collections import defaultdict

LOG_FILE = "data/sample/entra_oauth_consents.csv"
HIGH_RISK_SCOPES = {"Mail.Read", "Files.Read.All", "Directory.Read.All"}

# Track known IPs per user
known_ips = defaultdict(set)
alerts = []

with open(LOG_FILE, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        user = row["username"]
        ip = row["ip_address"]
        scopes = set(s.strip() for s in row["scopes"].split(","))

        risky_scopes = bool(scopes & HIGH_RISK_SCOPES)
        new_ip = ip not in known_ips[user]

        # Register IP as seen
        known_ips[user].add(ip)

        if (
            row["consent_type"] == "user"
            and row["is_new_app"] == "true"
            and row["publisher"] == "Unknown"
            and risky_scopes
        ):
            severity = "MEDIUM"
            reason = "Suspicious OAuth consent with high-risk scopes"

            if new_ip:
                severity = "HIGH"
                reason = "OAuth consent from new IP with high-risk scopes"

            alerts.append({
                "user": user,
                "app": row["app_name"],
                "scopes": scopes,
                "ip": ip,
                "severity": severity,
                "reason": reason
            })

for a in alerts:
    print("[ALERT] Suspicious OAuth App Consent")
    print(f"        User: {a['user']}")
    print(f"        App: {a['app']}")
    print(f"        Scopes: {', '.join(a['scopes'])}")
    print(f"        Source IP: {a['ip']}")
    print(f"        Severity: {a['severity']}")
    print(f"        Reason: {a['reason']}")
