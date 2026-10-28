# 📦 KMS-Envelope-Encryption-Auditor CLI (Envelope Pattern & Data Key Governance)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**KMS-Envelope-Encryption-Auditor** is an advanced Python-based CLI tool designed to audit KMS Customer Master Keys (CMKs) configured for envelope encryption pipelines (such as S3, EBS, and custom application encryption). Recognizing that KMS has a 4KB payload limit and throughput constraints, this tool verifies that keys designated for data encryption possess correct usage permissions (`GenerateDataKey`, `Decrypt`) and policy guardrails.

## ✨ Key Features

- **Envelope Encryption Readiness Audit:** Inspects KMS CMK policies to ensure workloads have authorized access to `kms:GenerateDataKey` (for encryption) and `kms:Decrypt` (for decryption).
- **Key Usage Validation:** Verifies that CMKs supporting data encryption are configured with `ENCRYPT_DECRYPT` key usage.
- **Security Boundary Enforcement:** Ensures application workflows correctly implement the envelope pattern without attempting to store plaintext data keys or bypass KMS boundaries.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if compliant, `1` if cryptographic permission or envelope security gaps are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate envelope encryption KMS keys and policies locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python envelope_encryption_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python envelope_encryption_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python envelope_encryption_cli.py audit --profile production --output ./reports/envelope_encryption_audit.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "Envelope Encryption: Encrypt large data locally using a symmetric Data Key, secure the Data Key via KMS GenerateDataKey, and ensure CMKs never leave KMS in plaintext.",
        "total_checks": 2,
        "failed_checks": 0
    },
    "findings": [
        {
            "resource_type": "KMS Customer Master Key",
            "resource_name": "arn:aws:kms:us-east-1:123456789012:key/envelope-key-uuid",
            "check": "Envelope Encryption Capability (GenerateDataKey)",
            "status": "PASS",
            "detail": "CMK is active and fully configured to support GenerateDataKey and Decrypt operations for envelope encryption."
        }
    ]
}
```