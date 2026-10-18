# 🛡️ IAM-Core-Auditor CLI (Users vs Roles vs Policies)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**IAM-Core-Auditor** is a Python-based CLI (Command Line Interface) tool designed to evaluate core **Identity and Access Management (IAM)** security hygiene in an AWS environment. Based on the fundamental cloud security principle—**"Identity is the new perimeter"**—this tool audits identity configurations, separating human users from workload roles and inspecting trust boundaries.

Instead of relying on insecure long-term credentials or over-permissive trust relationships, IAM-Core-Auditor systematically inventories and validates primary IAM risk vectors: checking human users for risky, long-term access keys and parsing IAM Role Trust Policies to catch dangerous wildcard principals or unauthorized cross-account bindings.

## ✨ Key Features

- **Identity Posture Scanning:** Verifies strict separation between human users (long-term keys) and workload identities (roles).
- **Trust Policy Inspection:** Analyzes IAM Role assume-role trust documents to detect wildcard principals (`*`) and over-permissive access.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` for success, `1` if IAM security violations are found), allowing automated security gates in DevSecOps pipelines.
- **JSON Reporting:** Generates a structured, machine-parsable results file using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate secure and vulnerable IAM setups in RAM safely without connecting to a live AWS account.

## 🚀 Installation

1. Clone the repository and navigate to the project folder.
2. (Optional) Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install required dependencies:
```bash
pip install boto3 moto

---

## 🛠️ Usage
The tool uses standard library `argparse` for a robust command-line interface.
Display help menu:
```bash
python iam_core_cli.py -h
```

1.Run audit in an isolated virtual environment (Mock Mode):
```bash
python iam_core_cli.py audit --mock
```

2. Audit a real AWS account using a profile and save the JSON report:

```bash
python iam_core_cli.py audit --profile production-profile --output ./reports/iam_core_audit_report.json
```

---

## 📊 Sample Output (JSON)

```bash
{
    "metadata": {
        "philosophy": "IAM Core: Enforce strict separation between human users and workload roles, validating trust boundaries.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "IAM User",
            "resource_name": "legacy-contractor",
            "iam_pillar": "Identity Hygiene",
            "check": "Active Long-term Access Keys",
            "status": "FAIL"
        }
    ]
}
``` 