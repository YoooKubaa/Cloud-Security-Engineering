# 🔒 Encryption-Defaults-Auditor CLI (S3 & EBS Automated Rest Encryption)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**Encryption-Defaults-Auditor** is an advanced Python-based CLI tool designed to audit automated encryption defaults across AWS storage services. Recognizing that human error is the primary vector for unencrypted cloud resources, this tool evaluates **S3 Bucket Default Encryption** configurations (distinguishing between basic SSE-S3 and auditable SSE-KMS) and verifies regional **EBS Encryption by Default** settings to eliminate unencrypted storage sprawl.

## ✨ Key Features

- **S3 Default Encryption Audit:** Inventories S3 buckets and inspects their default encryption configurations (SSE-S3 vs. Customer-Managed SSE-KMS).
- **EBS Account-Level Enforcement:** Checks whether regional EBS "Encryption by Default" is active, ensuring new block storage volumes are never created unencrypted.
- **Compliance Alignment:** Enforces rigorous data-at-rest standards required by enterprise compliance frameworks (PCI-DSS, SOC2, HIPAA).
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if storage encryption defaults are fully active, `1` if unencrypted storage postures are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate secure and unencrypted storage states locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python encryption_defaults_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python encryption_defaults_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python encryption_defaults_cli.py audit --profile production --output ./reports/encryption_defaults_audit.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "Encryption Defaults: Eliminate human error by enforcing automatic encryption at rest across S3 and EBS, prioritizing auditable SSE-KMS for fintech compliance.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "S3 Bucket",
            "resource_name": "unencrypted-legacy-bucket",
            "check": "S3 Default Encryption",
            "status": "FAIL",
            "detail": "S3 bucket lacks active default encryption configuration."
        }
    ]
}
```