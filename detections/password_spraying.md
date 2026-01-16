# Password Spraying Detection

## Detection Idea
This detection identifies potential password spraying attacks
by correlating failed authentication attempts across multiple
user accounts from a single source IP within a short time window.

## Why This Is Suspicious
Legitimate users rarely attempt to authenticate
to multiple different accounts in rapid succession.

## Detection Thresholds
- Distinct users: ≥ 5
- Time window: 2 minutes
- Signal: failed logins (optional success correlation later)

## Known Limitations
- Shared IP environments (VPN, NAT)
- Jump servers
- Poorly configured service accounts
