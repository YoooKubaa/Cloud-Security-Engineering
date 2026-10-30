# 🔄 KMS-Rotation-Auditor CLI (Cryptographic Material Lifecycle Governance)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**KMS-Rotation-Auditor** is a Python-based CLI tool designed to audit cryptographic key rotation postures across AWS Customer Master Keys (CMKs). Recognizing that annual key rotation minimizes the blast radius of potential key material exposure without disrupting legacy data decryption or availability, this tool enforces active rotation policies across all organizational encryption keys.

## ✨ Key Features

- **Key Rotation Status Audit:** Inventories customer-managed KMS keys and checks whether annual automatic key rotation (`KeyRotationEnabled`) is active.
- **Blast Radius Reduction:** Flags unrotated CMKs that rely on static cryptographic material indefinitely, mitigating long-term compromise risks.
- **Compliance Enforcement:** Ensures adherence to financial and enterprise security frameworks (e.g., SOC2, PCI-DSS) requiring regular cryptographic material updates.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if all CMKs have rotation enabled, `1` if unrotated customer keys are discovered) to block insecure infrastructure.
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate rotated and unrotated KMS key states locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python key_rotation_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python key_rotation_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python key_rotation_cli.py audit --profile production --output ./reports/kms_rotation_audit.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "KMS Key Rotation: Periodically rotate cryptographic material annually while maintaining the same Key ARN, minimizing blast radius without requiring data re-encryption.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "KMS Customer Master Key",
            "resource_name": "arn:aws:kms:us-east-1:123456789012:key/unrotated-key-uuid",
            "check": "Annual Key Rotation Enabled",
            "status": "FAIL",
            "detail": "Customer Managed Key does not have automatic annual key rotation enabled."
        }
    ]
}
```