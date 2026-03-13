# Splunk Detection Rule Library

A curated repository of custom Splunk SPL (Search Processing Language) detection rules designed to identify advanced adversary techniques. All rules are mapped directly to the [MITRE ATT&CK framework](https://attack.mitre.org/).

## Overview
This library focuses on high-fidelity detections for critical phases of the attack lifecycle, including:
* **Credential Access:** Credential Dumping (T1003)
* **Defense Evasion / Privilege Escalation:** Process Injection (T1055)
* **Command and Control:** Application Layer Protocol / Beaconing (T1071)

## Repository Structure
* `/rules/`: Contains individual Markdown files for each detection. Every rule includes the SPL query, MITRE mapping, logical explanation, tuning recommendations, and known false positives.
* `/templates/`: Contains the standard template used for documenting new rules to ensure consistency.

## Methodology
Detections are built assuming ingestion of high-quality telemetry, specifically **Windows Sysmon** (Event IDs 1, 3, 8, 10) and standard Windows Security Event Logs (Event IDs 4688, 4624).
