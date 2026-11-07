# 🔍 CloudTrail-Auditor CLI (API Telemetry, Multi-Region Governance & Log Integrity)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**CloudTrail-Auditor** is an advanced Python-based CLI tool designed to audit AWS CloudTrail configurations across multi-account and multi-region environments. Recognizing that CloudTrail is the bedrock of all incident response and threat detection, this tool verifies active logging status, multi-region coverage, cryptographic log file validation, and data event configurations to eliminate security blind spots.

## ✨ Key Features

- **Multi-Region Trail Audit:** Verifies that CloudTrail trails capture API activity globally across all AWS regions rather than being siloed in a single region.
- **Log File Validation Inspection:** Checks whether cryptographic hash-chain log file validation is enabled to detect unauthorized post-collection tampering.
- **Active Logging State Enforcement:** Ensures trails are actively recording events and flags stopped or paused logging pipelines.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if CloudTrail posture is fully compliant, `1` if unmonitored regions, disabled validation, or stopped trails are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate compliant and misconfigured CloudTrail setups locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python cloudtrail_auditor_cli.py -h
``` 

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python cloudtrail_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python cloudtrail_auditor_cli.py audit --profile production --output ./reports/cloudtrail_audit.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "CloudTrail Visibility: Capture every API call across multi-region environments with cryptographic log file validation enabled to ensure tamper-proof incident forensics.",
        "total_checks": 3,
        "failed_checks": 0
    },
    "findings": [
        {
            "resource_type": "CloudTrail",
            "resource_name": "prod-audit-trail",
            "check": "Multi-Region Coverage",
            "status": "PASS",
            "detail": "CloudTrail is configured as a multi-region trail."
        }
    ]
}
```