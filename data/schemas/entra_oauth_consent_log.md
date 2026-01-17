# Entra ID OAuth Consent Log Schema

| Field          | Description |
|----------------|-------------|
| timestamp      | Event time (UTC) |
| username       | User granting consent |
| app_name       | OAuth application name |
| app_id         | Application (client) ID |
| consent_type   | user / admin |
| scopes         | OAuth scopes granted |
| is_new_app     | true/false |
| publisher      | Verified publisher name |
| ip_address     | Source IP |
| log_source     | entra_id |
