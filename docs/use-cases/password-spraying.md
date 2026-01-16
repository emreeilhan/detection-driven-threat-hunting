# Password Spraying Detection

## MITRE ATT&CK
- Tactic: Credential Access
- Technique: T1110 – Brute Force / Password Spraying

## Threat Hypothesis
If an attacker performs password spraying,
we expect to observe multiple failed authentication attempts
across different user accounts from a limited set of source IPs
within a short time window, potentially followed by a successful login.

## Expected Signals
- High number of failed logins
- Same source IP targeting multiple usernames
- Short time window between attempts

## Detection Challenges
- Shared IPs (NAT, VPN)
- Legitimate user mistakes
- Service accounts
