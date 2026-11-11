# 🔒 S3-Immutability-Auditor CLI (Log Protection, Object Lock & Tamper-Proof Forensics)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**S3-Immutability-Auditor** is an advanced Python-based CLI tool designed to audit S3 buckets configured for security log storage (CloudTrail, VPC Flow Logs, application telemetry). Upholding the core security principle *"You cannot secure what you cannot log"*, this tool verifies that log storage buckets enforce **Versioning** and **S3 Object Lock** (Compliance or Governance mode) to guarantee absolute immutability and prevent post-incident log deletion or tampering by sophisticated attackers.

## ✨ Key Features

- **S3 Object Lock Inspection:** Scans log buckets to ensure Object Lock is actively enabled, preventing objects from being overwritten or deleted even by root users (WORM storage).
- **Versioning Enforcement:** Verifies that S3 bucket versioning is active as a mandatory prerequisite for retention governance.
- **Compliance & Forensics Readiness:** Ensures adherence to strict regulatory retention mandates (PCI-DSS, SOC2, SEC Rule 17a-4).
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if log buckets are fully immutable, `1` if mutable log buckets vulnerable to tampering are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate immutable and vulnerable log buckets locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python immutability_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python immutability_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python immutability_auditor_cli.py audit --profile production --output ./reports/immutability_audit.json
```

## 📊 Sample Output (JSON)

```json 
{
    "metadata": {
        "philosophy": "You cannot secure what you cannot log: Ensure log storage buckets are strictly immutable using S3 Object Lock and Versioning to prevent tamper attacks during incidents.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "S3 Bucket",
            "resource_name": "mutable-legacy-logs",
            "check": "S3 Object Lock Enabled",
            "status": "FAIL",
            "detail": "Log bucket lacks S3 Object Lock. Logs can be modified or deleted by compromised credentials."
        }
    ]
}
```