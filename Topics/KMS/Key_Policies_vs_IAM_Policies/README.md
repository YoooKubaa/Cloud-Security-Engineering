# 🛡️ KMS-Policy-Auditor CLI (Resource-Based vs Identity-Based Authorization)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**KMS-Policy-Auditor** is a Python-based CLI tool designed to audit KMS Customer Master Key (CMK) resource-based policies (Key Policies) and evaluate how they intersect with IAM identity-based policies. Recognizing that KMS requires both Key Policies and IAM Policies to grant explicit permission (`AND` logic), this tool inspects key policies for dangerous over-privilegement, missing IAM delegation statements (`Enable IAM User Permissions`), and external principal risks.

## ✨ Key Features

- **Key Policy Delegation Audit:** Inspects KMS key policies to verify whether IAM policy delegation is enabled or if the key is locked down to explicit IAM entities.
- **Over-Permissive Principal Detection:** Flags key policies that grant administrative or usage permissions to wildcard principals (`*` or unconstrained external AWS accounts).
- **Effective Permission Analysis:** Evaluates the dual-policy requirement (`Key Policy AND IAM Policy`) to prevent common misconfigurations that break decryption or management pipelines.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if compliant, `1` if dangerous key policy patterns or missing delegation scopes are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate secure and misconfigured KMS key policies locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python key_policy_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python key_policy_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python key_policy_auditor_cli.py audit --profile production --output ./reports/kms_policy_audit.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "Key Policies vs IAM Policies: KMS effective permissions require BOTH Key Policy AND IAM Policy to allow access (AND logic). Removing IAM delegation locks down the key entirely.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "KMS Key Policy",
            "resource_name": "arn:aws:kms:us-east-1:123456789012:key/locked-down-key",
            "check": "IAM Policy Delegation Statement",
            "status": "WARN",
            "detail": "Key policy does not delegate permissions to IAM user/role policies (missing 'Enable IAM User Permissions' statement). Direct key policy entries required."
        }
    ]
}
```