# Suspicious OAuth App Consent

## Context
Attackers abuse OAuth app consent to obtain long-lived access tokens,
bypassing MFA and persisting access even after password resets.

## Core Hypothesis
If a user grants OAuth consent to an application with high-risk permissions
(e.g., Mail.Read, Files.Read.All) that is newly created or uncommon in the tenant,
this strongly suggests identity abuse or social engineering.

## Expected Signals
- User-granted consent (not admin-only)
- High-risk scopes (mail, files, directory)
- New or low-reputation app
- Consent outside business hours (optional)
- First-time consent by the user

## Severity
HIGH when:
- High-risk scopes are granted
- AND the app is new or uncommon
- AND consent is user-initiated

MEDIUM when:
- App is known but scopes are elevated
