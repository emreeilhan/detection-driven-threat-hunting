# Detection-Driven Threat Hunting Mini Platform

## Objective

This project focuses on **hypothesis-driven threat hunting** and **detection logic development** using log-derived signals.

The platform emphasizes **correlation-based detections**, where multiple weak indicators are combined to produce **high-confidence security alerts**, reflecting how real SOC teams reason about threats.

---

## Why This Project Exists

Most beginner projects focus on isolated alerts or single log events.

This project exists to practice how **SOC analysts and detection engineers actually think**:

> raw logs → hypothesis → detection logic → correlation → confidence → response decision

The goal is not volume, but **signal quality and reasoning clarity**.

---

## Detection Philosophy

This platform deliberately avoids single-event alerts.

Each detection is designed to:

- Start from a realistic attacker behavior
- Combine multiple weak signals
- Reduce false positives through context and correlation
- Assign severity based on **confidence**, not guesswork

This mirrors real-world SOC decision-making rather than academic examples.

---

## Detection Scope

This project currently focuses on **identity-based attack techniques** commonly observed in modern cloud and enterprise environments.

The implemented detections model a realistic **identity compromise lifecycle**, rather than standalone or unrelated alert scenarios.

---

## Implemented Detection Scenarios

The following detection scenarios are currently implemented:

### Password Spraying

Detection of credential access attempts across multiple user accounts from a single source IP within a short time window, with **fail-to-success correlation** to confirm compromise.

### Impossible Travel

Identification of authentication events from geographically distant locations within an unrealistic time window, indicating credential misuse or session hijacking.

### Suspicious OAuth App Consent

Detection of high-risk OAuth consent grants involving:

- Unknown or newly created applications
- Sensitive permission scopes
- Anomalous IP or session behavior

This scenario models post-compromise persistence via token abuse.

These detections intentionally **complement each other** to demonstrate how identity-based attacks progress from initial access to persistence.

---

## Repository Structure

```
data/
 ├── sample/        # Sample log datasets (CSV)
 └── schemas/       # Log field definitions and documentation

detections/
 ├── password_spraying.py
 ├── password_spraying.md
 ├── password_spraying_sigma.yml
 ├── impossible_travel.py
 ├── suspicious_oauth_consent.py
 └── suspicious_oauth_consent.md

docs/
 └── README.md
```

Each detection includes:

- Working detection logic (Python)
- Clear documentation explaining **why** the detection exists
- Explicit severity and confidence reasoning

---

## MITRE ATT&CK Mapping

- **T1110 – Brute Force / Password Spraying**
- **T1078 – Valid Accounts**
- **T1528 – Steal Application Access Token**

Mappings are included to provide tactical context, not checklist compliance.

---

## Intended Audience

This project is designed for:

- SOC Analysts (Tier 1–2)
- Detection Engineers
- Threat Hunters
- Blue team learners focusing on **reasoning**, not tools

---

## Disclaimer

All data in this repository is **synthetic and non-production**. The project is intended solely for educational and skill-building purposes.

