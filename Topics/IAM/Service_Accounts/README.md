# 🔗 Service-Accounts-Auditor CLI (Cross-Account Access & Confused Deputy Protection)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**Service-Accounts-Auditor** is a Python-based CLI tool designed to audit service accounts and cross-account IAM trust relationships in AWS environments. It enforces rigorous security standards for non-human workloads and third-party integrations, specifically validating **Cross-Account Role Assumptions** and checking for mandatory **ExternalId** scopes to mitigate *Confused Deputy* vulnerabilities.

## ✨ Key Features

- **Cross-Account Trust Inspection:** Scans IAM role trust policies for external principal ARNs or foreign AWS account IDs.
- **Confused Deputy Mitigation (`ExternalId`):** Verifies that third-party cross-account roles enforce strict `ExternalId` condition blocks, preventing unauthorized resource hijacking.
- **Workload Credential Hygiene:** Detects anti-pattern service accounts relying on long-term static access keys instead of ephemeral IAM roles.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if secure, `1` if cross-account or service account violations are detected) to block vulnerable configurations.
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate secure and insecure cross-account trust setups locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python service_accounts_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python service_accounts_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python service_accounts_cli.py audit --profile production --output ./reports/cross_account_audit.json
```

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "Service Accounts & Cross-Account Access: Enforce temporary roles, eliminate static keys, and mandate ExternalId for cross-account trust.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "IAM Role (Cross-Account)",
            "resource_name": "InsecureThirdPartyRole",
            "check": "Confused Deputy Protection (ExternalId)",
            "status": "FAIL",
            "detail": "Cross-account trust policy allows an external principal without requiring a mandatory ExternalId condition block."
        }
    ]
}
```