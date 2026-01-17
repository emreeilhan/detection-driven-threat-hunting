# Suspicious OAuth App Consent

## Detection Summary
This detection identifies potentially malicious OAuth applications
that obtain high-privilege access through user consent.

## Why This Is Dangerous
OAuth tokens can persist beyond password resets and MFA changes,
allowing attackers long-term access to email, files, and APIs.

## Severity Rationale
HIGH severity is assigned when a user grants high-risk scopes
to a newly created or unknown application, indicating likely
social engineering or token abuse.
