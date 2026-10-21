# 🚧 Boundary-Auditor CLI (IAM Permission Boundaries)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**Boundary-Auditor** is a Python-based CLI tool designed to audit IAM Permission Boundaries in AWS environments. Serving as the primary security guardrail for safe self-service delegation, permission boundaries act as a hard ceiling (intersection logic) limiting effective permissions regardless of identity-based policies.

This tool audits IAM users and workload roles to ensure that critical or self-service identities enforce appropriate permission boundaries, preventing accidental privilege escalation and policy drift.

## ✨ Key Features

- **Boundary Enforcement Scanning:** Inventories IAM users and roles to verify whether a Permission Boundary is attached.
- **Self-Service Hygiene:** Detects unconstrained IAM principals in delegation zones that lack maximum privilege ceilings.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if compliant, `1` if boundary violations are detected) to block insecure infrastructure configurations.
- **JSON Reporting:** Generates structured, machine-parsable audit reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate secure and unconstrained IAM boundaries locally in RAM.

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
python boundary_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python boundary_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python boundary_auditor_cli.py audit --profile production --output ./reports/boundary_audit.json
```

---

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "Permission Boundaries: Enforce a hard security ceiling for self-service delegation using intersection logic.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "IAM Role",
            "resource_name": "unconstrained-dev-role",
            "check": "Permission Boundary Attached",
            "status": "FAIL",
            "detail": "Role lacks a permission boundary, leaving effective permissions unconstrained."
        }
    ]
}
```