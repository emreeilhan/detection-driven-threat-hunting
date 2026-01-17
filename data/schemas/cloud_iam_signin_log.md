# Cloud IAM Sign-in Log Schema

| Field        | Description |
|-------------|-------------|
| timestamp   | Event time (UTC) |
| username    | Account identifier |
| source_ip   | Source IP address |
| result      | success / failure |
| country     | Country derived from GeoIP |
| city        | City derived from GeoIP |
| asn         | ASN number (optional) |
| user_agent  | User agent / client (optional) |
| device_id   | Device identifier (optional) |
| log_source  | e.g., entra_id, okta, gsuite |
