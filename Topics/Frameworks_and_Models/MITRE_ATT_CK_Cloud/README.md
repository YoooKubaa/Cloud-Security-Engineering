# 🛡️ CAM-Mapper CLI (Cloud ATT&CK Mapper)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK-Cloud-orange)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**CAM-Mapper** is a Python-based CLI (Command Line Interface) tool designed to bridge the gap between cloud telemetry and threat intelligence. It parses cloud log events (such as AWS CloudTrail JSON logs) and automatically maps suspicious API calls against the **MITRE ATT&CK for Cloud Matrix**.

Instead of manual log triage, CAM-Mapper identifies adversary behaviors across tactics like *Discovery*, *Persistence*, *Defense Evasion*, and *Collection*, transforming raw JSON events into actionable technique IDs.

## ✨ Key Features

- **ATT&CK Technique Mapping:** Translates native cloud API activity (e.g., `CreateAccessKey`, `StopLogging`) into standardized MITRE ATT&CK IDs (e.g., T1098.001, T1562.008).
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if no high-risk techniques detected, `1` if malicious/suspicious adversary patterns are identified).
- **JSON Reporting:** Generates structured, machine-parsable analysis reports using native `json` and `pathlib` libraries.
- **Built-in Sample Generator:** Features a `--sample` flag to instantly generate and analyze a synthetic malicious CloudTrail log file for quick testing.

## 🚀 Installation

1. Clone the repository and navigate to the project folder.
2. (Optional) Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. No external SDK required for core parsing (pure Python standard library), making it lightweight and lightning-fast!

## 🛠️ Usage
The tool uses standard library `argparse` for command-line execution.
Display help menu:
```bash
python cam_mapper.py -h
```

1. Generate and analyze a sample malicious log file (Demo Mode):
```bash
python cam_mapper.py analyze --sample
```

2. Analyze a custom CloudTrail log file and save the JSON report:
```bash
python cam_mapper.py analyze --input ./logs/cloudtrail_events.json --output ./reports/cam_analysis.json
```

---

## 📊 Sample Output (JSON)

```bash
{
    "metadata": {
        "philosophy": "Cloud ATT&CK Mapper: Translating cloud telemetry into actionable threat intelligence.",
        "total_events_analyzed": 3,
        "matched_techniques_count": 2
    },
    "mapped_findings": [
        {
            "event_name": "CreateAccessKey",
            "username": "compromised-dev",
            "tactic": "Persistence",
            "technique_id": "T1098.001",
            "technique_name": "Account Manipulation: Additional Cloud Credentials",
            "severity": "HIGH"
        },
        {
            "event_name": "StopLogging",
            "username": "attacker",
            "tactic": "Defense Evasion",
            "technique_id": "T1562.008",
            "technique_name": "Impair Defenses: Disable Cloud Trail",
            "severity": "CRITICAL"
        }
    ]
}
```
