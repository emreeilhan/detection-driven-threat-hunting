# Suspicious OAuth App Consent

## Detection Summary
This detection identifies potentially malicious OAuth applications
that obtain high-privilege access through user-initiated consent.

## Why This Is Dangerous
OAuth access and refresh tokens are not automatically revoked
after password resets or MFA changes, enabling long-term access
to user data and APIs.

## Detection Logic
- User-initiated consent
- High-risk scopes (Mail, Files, Directory)
- New or uncommon application
- Unknown publisher

## Severity Assessment
- MEDIUM: New app with high-risk scopes
- HIGH: New app with high-risk scopes from a previously unseen IP

## Common False Positives
- Legitimate internal applications
- Developer testing environments

## Confidence Enhancement
Severity is increased when OAuth consent originates
from a new IP address for the user, reducing the
likelihood of legitimate behavior.
