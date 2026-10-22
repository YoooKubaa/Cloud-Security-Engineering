# ⚡ Abuse-Auditor CLI (Privilege Escalation & Abuse Patterns)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**Abuse-Auditor** is a Python-based CLI tool designed to detect dangerous IAM abuse patterns and privilege escalation vectors in AWS environments. Moving beyond simple list-based checks, this tool identifies complex misconfigurations such as admin sprawl, long-lived access keys, and dangerous permission combinations (e.g., `iam:PassRole` abuse vectors, policy version manipulation, and direct administrative policy attachments).

## ✨ Key Features

- **Privilege Escalation Detection:** Scans for dangerous IAM inline/managed policy statements that allow self-escalation (e.g., `iam:CreatePolicyVersion`, `iam:PutUserPolicy`, `iam:UpdateAssumeRolePolicy`).
- **Admin Sprawl Audit:** Flags over-permissive identities holding `AdministratorAccess` managed policies.
- **Credential Hygiene:** Identifies high-risk, long-lived user access keys that increase the lateral movement window.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if clean, `1` if privilege escalation vectors are detected) to block insecure builds.
- **JSON Reporting:** Generates structured, machine-parsable audit reports for security telemetry.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using `moto` to simulate vulnerable IAM architectures locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

---

## 🛠️ Usage
Display help menu:
```bash
python abuse_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python abuse_auditor_cli.py scan --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python abuse_auditor_cli.py scan --profile production --output ./reports/abuse_audit.json
```

---

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "Abuse Patterns: Proactively hunt for privilege escalation paths, admin sprawl, and dangerous permission combinations.",
        "total_checks": 3,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "IAM User",
            "resource_name": "developer-sandbox",
            "check": "Privilege Escalation Vector (iam:CreatePolicyVersion)",
            "status": "FAIL",
            "detail": "User possesses permissions to create a new version of their own policy, allowing full admin escalation."
        }
    ]
}
```
