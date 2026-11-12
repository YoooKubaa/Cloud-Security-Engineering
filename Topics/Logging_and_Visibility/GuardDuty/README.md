# 🛡️ GuardDuty-Auditor CLI (Managed ML Threat Detection & Telemetry Coverage)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**GuardDuty-Auditor** is an advanced Python-based CLI tool designed to audit Amazon GuardDuty detector statuses, data source telemetry configurations (CloudTrail, VPC Flow Logs, DNS, S3, EKS audit logs, and Malware Protection), and multi-account administrative aggregations. Recognizing that GuardDuty provides critical baseline machine learning and threat intelligence that complements custom detection rules, this tool eliminates security blind spots by ensuring threat detectors are active and fully provisioned across cloud environments.

## ✨ Key Features

- **Detector Status Audit:** Verifies that GuardDuty detectors are enabled and operational within target regions.
- **Data Source Coverage Inspection:** Audits underlying telemetry feeds (S3 logs, Kubernetes audit logs, and EBS malware scanning) to ensure comprehensive visibility.
- **Multi-Account Governance:** Identifies standalone vs. multi-account administrator/member relationships.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if GuardDuty posture is fully enabled, `1` if disabled detectors or missing data sources are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate active and misconfigured GuardDuty environments locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python guardduty_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python guardduty_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python guardduty_auditor_cli.py audit --profile production --output ./reports/guardduty_audit.json
```

## 📊 Sample Output (JSON)

```json 
{
    "metadata": {
        "philosophy": "GuardDuty Threat Detection: Leverage managed machine learning and threat intelligence feeds to catch anomalous behavior, complementing custom architecture-specific detection rules.",
        "total_checks": 2,
        "failed_checks": 0
    },
    "findings": [
        {
            "resource_type": "GuardDuty Detector",
            "resource_name": "detector-mock-id",
            "check": "Detector Active Status",
            "status": "PASS",
            "detail": "GuardDuty detector is enabled and actively monitoring telemetry feeds."
        }
    ]
}
```