import csv

LOG_FILE = "data/sample/entra_oauth_consents.csv"
HIGH_RISK_SCOPES = {"Mail.Read", "Files.Read.All", "Directory.Read.All"}

alerts = []

with open(LOG_FILE, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        scopes = set(s.strip() for s in row["scopes"].split(","))
        risky = bool(scopes & HIGH_RISK_SCOPES)

        if (
            row["consent_type"] == "user"
            and row["is_new_app"] == "true"
            and risky
            and row["publisher"] == "Unknown"
        ):
            alerts.append({
                "user": row["username"],
                "app": row["app_name"],
                "scopes": scopes
            })

for a in alerts:
    print("[ALERT] Suspicious OAuth App Consent")
    print(f"        User: {a['user']}")
    print(f"        App: {a['app']}")
    print(f"        Scopes: {', '.join(a['scopes'])}")
    print("        Severity: HIGH")
