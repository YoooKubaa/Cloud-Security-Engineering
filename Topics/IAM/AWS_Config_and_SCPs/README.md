# 🛡️ Config-SCP-Auditor CLI (Organizational Guardrails & Continuous Compliance)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**Config-SCP-Auditor** is an advanced Python-based CLI tool designed to audit organizational-wide guardrails and continuous compliance postures in multi-account AWS environments. Moving beyond point-in-time checks, this tool validates **Service Control Policies (SCPs)** at the AWS Organizations / OU level to guarantee unbypassable safety ceilings (e.g., protecting critical detective controls like CloudTrail) and evaluates **AWS Config** recorder status and compliance rules.

## ✨ Key Features

- **SCP Guardrail Enforcement:** Inventories Service Control Policies across organizational units to verify critical `Explicit Deny` guardrails (such as preventing the disabling of logging or public exposure).
- **AWS Config Posture Audit:** Inspects AWS Config recording mechanisms and evaluation rules to ensure continuous compliance tracking.
- **Multi-Account Governance:** Operates at the organizational root to guarantee security controls cascade down to all current and future accounts.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if compliant, `1` if critical organizational guardrails are missing) to block insecure enterprise baselines.
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate organizational SCP structures and config recorders locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python config_scp_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python config_scp_auditor_cli.py audit --mock
```

2. Audit a real AWS account/organization and save the JSON report:
```bash
python config_scp_auditor_cli.py audit --profile production --output ./reports/config_scp_audit.json
```

## 📊 Sample Output (JSON)

```json 
{
    "metadata": {
        "philosophy": "AWS Config & SCPs: Enforce unbypassable organizational guardrails at the AWS Organizations level and continuous compliance evaluation.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "AWS Organizations SCP",
            "resource_name": "Root-Guardrails-SCP",
            "check": "Critical Logging Protection Deny",
            "status": "FAIL",
            "detail": "Organizational SCP is missing an explicit Deny rule protecting CloudTrail or GuardDuty from disabling."
        }
    ]
}
```