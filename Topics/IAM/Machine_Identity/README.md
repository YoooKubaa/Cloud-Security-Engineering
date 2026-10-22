# 🤖 Machine-Identity-Auditor CLI (Workload Identities & Metadata Security)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**Machine-Identity-Auditor** is a Python-based CLI tool designed to audit non-human (workload) identities in AWS environments. Recognizing that over 90% of cloud identities belong to machines (EC2 instances, Lambda functions, containers), this tool enforces secure architecture principles: eliminating hardcoded access keys on service accounts, enforcing **IMDSv2** to prevent SSRF credential theft, and verifying proper **Instance Profile / IRSA** role bindings.

## ✨ Key Features

- **Anti-Pattern Detection:** Flags IAM users with service-like names (e.g., `app`, `bot`, `service`) that rely on risky, long-term static access keys instead of IAM roles.
- **Compute Metadata Hardening (IMDSv2):** Audits EC2 instances to ensure Instance Metadata Service Version 2 is strictly required, mitigating SSRF-based credential hijacking.
- **Instance Profile Validation:** Verifies that compute workloads are bound to proper IAM instance profiles.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if posture is secure, `1` if machine identity violations are detected) to block insecure infrastructure.
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate secure and vulnerable workload configurations locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

---

## ️🛠️ Usage
Display help menu:
```bash
python machine_identity_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python machine_identity_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python machine_identity_cli.py audit --profile production --output ./reports/machine_identity_audit.json
```

---

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "Machine Identity: Non-human workloads must use IAM roles with IMDSv2 protection, never long-term static access keys.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "IAM User (Service Account)",
            "resource_name": "legacy-app-service-account",
            "check": "Static Access Keys on Workload Identity",
            "status": "FAIL",
            "detail": "Service-like user possesses active long-term access keys. Workloads must use IAM Roles."
        }
    ]
}
```