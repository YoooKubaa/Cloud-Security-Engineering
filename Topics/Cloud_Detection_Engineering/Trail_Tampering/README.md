# 🚨 Trail-Tampering-Detector CLI (MITRE ATT&CK T1562.008 Defense Evasion)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![MITRE](https://img.shields.io/badge/MITRE_ATT&CK-T1562.008-red)

**Trail-Tampering-Detector** is an automated Python CLI threat detection tool engineered to identify **Defense Evasion** attempts against AWS CloudTrail logging pipelines (mapped to **MITRE ATT&CK T1562.008 — Impair Defenses: Disable or Modify Cloud Logs**). 

Before executing high-noise actions like data exfiltration or persistence, sophisticated adversaries attempt to "turn off the lights" by calling `StopLogging`, `DeleteTrail`, or subtly degrading telemetry via `UpdateTrail` (e.g., disabling multi-region tracking or cryptographic log file validation). Because AWS records these API calls right before the configuration takes effect, this tool parses CloudTrail event streams to detect tampering immediately.

## ✨ Key Features

- **Critical Tampering Detection:** Flags `StopLogging`, `DeleteTrail`, and `UpdateTrail` events across CloudTrail logs.
- **Subtle Degradation Inspection (`UpdateTrail`):** Analyzes request parameters on `UpdateTrail` calls to catch silent downgrades (disabling `IsMultiRegionTrail` or `EnableLogFileValidation`).
- **MITRE ATT&CK Enrichment:** Automatically tags findings with `T1562.008` metadata and severity classifications (`CRITICAL` vs `HIGH`) for immediate SOC triage.
- **CI/CD Ready (Pipeline Breaker):** Returns non-zero exit codes (`1`) whenever tampering indicators are detected.
- **Built-in Test Environment (Mocking):** Supports `--mock` mode to simulate realistic adversary defense evasion sequences locally in RAM without live AWS credentials.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python trail_tampering_detector_cli.py -h
```

1. Run the detector in mock mode (Simulated adversary defense evasion):
```bash
python trail_tampering_detector_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python trail_tampering_detector_cli.py audit --profile production --output ./reports/trail_tampering_audit.json
```

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "Trail Tampering Detection (MITRE T1562.008): Adversaries disable or degrade logging before executing noisy actions. Detect StopLogging, DeleteTrail, and subtle UpdateTrail downgrades immediately.",
        "mitre_technique": "T1562.008 - Impair Defenses: Disable or Modify Cloud Logs",
        "total_checks": 3,
        "failed_checks": 3
    },
    "findings": [
        {
            "resource_type": "CloudTrail",
            "resource_name": "prod-organization-trail",
            "actor": "compromised-admin",
            "event_name": "StopLogging",
            "severity": "CRITICAL",
            "status": "FAIL",
            "detail": "CRITICAL DEFENSE EVASION: Principal 'compromised-admin' executed StopLogging at 2026-11-16T20:10:00Z."
        }
    ]
}
```