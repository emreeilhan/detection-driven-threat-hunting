# Impossible Travel Detection

## Context
This use-case targets cloud identity compromise scenarios where an attacker reuses
stolen credentials or tokens from a different geography.

## Core Hypothesis
If the same user account authenticates from two distant locations within an
impossibly short time window, this strongly suggests token theft, session hijack,
or compromised credentials.

## Expected Signals
- Same user
- Two successful logins
- Different countries/cities
- Short time delta (e.g., < 60 minutes)
- Optional: different IPs / different ASNs / new device

## Detection Challenges (False Positives)
- VPN / corporate egress gateways
- Mobile networks
- GeoIP inaccuracies
- Legitimate travel + clock skew

## Severity
HIGH when:
- success → success impossible travel is observed
- AND the second login is from a new device, new ASN, or new IP
