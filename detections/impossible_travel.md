# Impossible Travel Detection

## Detection Summary
This detection identifies potential identity compromise
by correlating successful cloud authentication events
from geographically distant locations within a short time window.

## Why This Is Suspicious
Legitimate users cannot physically travel between distant
countries within minutes. Such patterns often indicate
stolen credentials, session hijacking, or token reuse.

## Detection Logic
- Same user
- Multiple successful logins
- Different countries
- Time difference below defined threshold (any subsequent login)

## Severity Assessment
- MEDIUM: Country change within time threshold
- HIGH: Country change combined with new ASN, new device, or new IP

## Common False Positives
- Corporate VPNs
- Cloud egress gateways
- Mobile network routing

## Why Severity Matters
Impossible travel combined with infrastructure changes
strongly suggests account compromise rather than
benign user behavior, requiring investigation.
