# 🛡️ ZT-Auditor CLI (Zero Trust Model)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**ZT-Auditor** is a Python-based CLI (Command Line Interface) tool designed to evaluate the **Zero Trust** security posture in an AWS environment. Based on the core Zero Trust principle—**"Never Trust, Always Verify"**—this tool audits infrastructure configurations that prevent lateral movement, credential theft, and unauthorized access.

Instead of relying on a traditional perimeter-based security model, ZT-Auditor inspects low-level architectural settings, such as enforcing **IMDSv2** (Instance Metadata Service Version 2) on EC2 instances to prevent SSRF credential hijacking, and validating strict **Security Group microsegmentation**.

## ✨ Key Features

- **Zero Trust Posture Scanning:** Verifies strict identity and infrastructure controls (e.g., IMDSv2 enforcement, least-privilege network boundaries).
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` for success, `1` if Zero Trust violations are found), allowing automated security gates in DevSecOps pipelines.
- **JSON Reporting:** Generates a structured, machine-parsable results file using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate secure and vulnerable EC2 instances in RAM safely without connecting to a live AWS account.

## 🚀 Installation

1. Clone the repository and navigate to the project folder.
2. (Optional) Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install required dependencies:
```bash
pip install boto3 moto
```

---

## 🛠️ Usage

The tool uses standard library `argparse` for a robust command-line interface.
Display help menu:
```bash
python zt_cli.py -h
```

1. Run audit in an isolated virtual environment (Mock Mode):
```bash
python zt_cli.py scan --mock
```

2. Scan a real AWS account using a profile and save the JSON report:
```bash
python zt_cli.py scan --profile production-profile --output ./reports/zt_audit_report.json
```

---

## 📊 Sample Output (JSON)
```bash
{
    "metadata": {
        "philosophy": "Zero Trust Model: Never Trust, Always Verify. Enforcing IMDSv2 and strict network boundaries.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "service": "EC2",
            "resource": "i-0123456789abcdef0",
            "zero_trust_pillar": "Compute Security (IMDSv2)",
            "check": "Metadata Service Version 2 Required",
            "status": "FAIL"
        }
    ]
}
```
