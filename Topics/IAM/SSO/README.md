# 🏢 SSO-Auditor CLI (IAM Identity Center & Multi-Account Governance)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**SSO-Auditor** is a Python-based CLI tool designed to audit Single Sign-On and multi-account governance postures in AWS environments utilizing **IAM Identity Center**. Moving away from fragmented native IAM user management across individual AWS accounts, this tool verifies centralized Identity Center deployment and hunts for legacy human IAM users with active console credentials (a major enterprise anti-pattern).

## ✨ Key Features

- **Identity Center Deployment Audit:** Inventories IAM Identity Center instances to verify centralized multi-account access governance.
- **Legacy Human User Detection:** Scans for native IAM users possessing active console login profiles, enforcing the transition to SSO and external IdPs (Azure AD, Okta).
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if compliant, `1` if legacy human users or missing SSO governance are detected) to block unsecure configurations.
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate multi-account SSO governance states locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python sso_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python sso_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python sso_auditor_cli.py audit --profile production --output ./reports/sso_audit.json
```

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "SSO & Identity Center: Centralize multi-account access via IAM Identity Center and eliminate legacy human IAM users.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "IAM User (Legacy Human)",
            "resource_name": "john.doe-admin",
            "check": "Legacy Console User Sprawl",
            "status": "FAIL",
            "detail": "User has an active console login profile. Human access should be managed via IAM Identity Center (SSO), not native IAM Users."
        }
    ]
}
```