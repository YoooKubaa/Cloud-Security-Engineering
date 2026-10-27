# 🔑 KMS-Key-Type-Auditor CLI (Symmetric vs Asymmetric Key Governance)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**KMS-Key-Type-Auditor** is a Python-based CLI tool designed to audit AWS KMS keys, distinguishing between **Symmetric (AES-256)** keys used for envelope encryption (S3, EBS, RDS) and **Asymmetric (RSA/ECC)** keys used for digital signatures and external verifications. It enforces architectural guardrails, ensuring that KMS key specifications match secure cryptographic standards and intended use cases.

## ✨ Key Features

- **Key Specification Audit:** Inventories KMS customer-managed keys (CMKs) and evaluates their `KeySpec` (e.g., `SYMMETRIC_DEFAULT` vs `RSA_2048`, `RSA_4096`).
- **Envelope Encryption Compliance:** Verifies that keys intended for data volume and object encryption are strictly symmetric.
- **Asymmetric Usage Validation:** Audits asymmetric keys to ensure they are properly designated for sign/verify or encrypt/decrypt operations, preventing misconfiguration anti-patterns.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if posture is secure, `1` if invalid key specs or risky cryptographic anti-patterns are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate symmetric and asymmetric key architectures locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python kms_key_type_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python kms_key_type_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python kms_key_type_cli.py audit --profile production --output ./reports/kms_key_audit.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "Symmetric vs Asymmetric: Symmetric keys (AES-256) power 95% of data encryption (envelope encryption), while Asymmetric keys (RSA/ECC) are reserved strictly for digital signatures and external verification.",
        "total_checks": 2,
        "failed_checks": 0
    },
    "findings": [
        {
            "resource_type": "KMS Customer Master Key",
            "resource_name": "arn:aws:kms:us-east-1:123456789012:key/sym-key-uuid",
            "check": "Cryptographic Key Spec",
            "status": "PASS",
            "detail": "Key specification is SYMMETRIC_DEFAULT, correctly configured for standard envelope encryption."
        }
    ]
}
```