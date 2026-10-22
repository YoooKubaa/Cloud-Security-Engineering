# 🛡️ CKC-Auditor CLI (Cloud Kill Chain Posture Auditor)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**CKC-Auditor** is a Python-based CLI (Command Line Interface) tool designed to audit an AWS environment for architectural misconfigurations that allow threat actors to progress along the **Cloud Kill Chain**. 

In cloud environments, compromise happens in minutes. Waiting for data exfiltration to detect an attack is a failure strategy. CKC-Auditor shifts security left by inspecting early-stage Kill Chain vectors:
1. **Initial Access & Persistence Risk:** Inspects long-lived IAM Access Keys and users.
2. **Privilege Escalation Risk:** Detects dangerous IAM policies (e.g., administrator privileges or role assumption paths).
3. **Defense Evasion Risk:** Verifies if audit logging (CloudTrail) is active and protected against blinding attacks (`stop-logging`).

## ✨ Key Features

- **Kill Chain Posture Analysis:** Evaluates structural flaws that accelerate cloud compromises.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` for clean posture, `1` if critical Kill Chain enablers are detected).
- **JSON Reporting:** Generates structured, machine-parsable JSON reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using `moto` to simulate insecure IAM and CloudTrail configurations safely in RAM.

## 🚀 Installation

1. Clone the repository and navigate to the project folder.
2. (Optional) Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install required dependencies:
```bash
pip install boto3 moto
```

---

## 🛠️ Usage
The tool uses standard library `argparse` for command-line execution.
Display help menu:
```bash
python ckc_cli.py -h
```

1. Run posture audit in an isolated virtual environment (Mock Mode):
```bash
python ckc_cli.py scan --mock
```

2. Scan a real AWS account and save the JSON report:
```bash
python ckc_cli.py scan --profile production-profile --output ./reports/ckc_audit_report.jsonpython ckc_cli.py scan --profile production-profile --output ./reports/ckc_audit_report.json
```

---

## 📊 Sample Output (JSON)
```json
{
    "metadata": {
        "philosophy": "Cloud Kill Chain: Prevent rapid compromise by detecting early-stage vectors (Discovery, PrivEsc, Defense Evasion).",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "service": "CloudTrail",
            "resource": "default-trail",
            "kill_chain_stage": "Defense Evasion",
            "check": "Audit Logging Active",
            "status": "PASS"
        }
    ]
}
```
