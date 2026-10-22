# 🛡️ ASM-Auditor CLI (AWS Attack Surface Management)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**ASM-Auditor** is a Python-based CLI (Command Line Interface) tool designed to map and evaluate the dynamic **Attack Surface** in an AWS environment. Because cloud environments constantly shift with automated deployments, ephemeral resources, and infrastructure-as-code, understanding external exposure is critical.

Instead of guessing what is exposed, ASM-Auditor systematically inventories and inspects primary external exposure points:
1. **Network Attack Surface:** Publicly accessible EC2 Security Groups (unrestricted ingress rules).
2. **Data Attack Surface:** S3 buckets lacking public access blocks.
3. **Identity Attack Surface:** Active long-lived IAM access keys serving as potential entry points.

## ✨ Key Features

- **Dynamic Surface Discovery:** Inventories public-facing assets and potential entry vectors across multiple AWS services.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if attack surface is minimal/controlled, `1` if unexpected public exposures are detected).
- **JSON Reporting:** Generates structured, machine-parsable JSON audit reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using `moto` to simulate complex, mixed-exposure cloud environments safely in RAM.

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
python asm_cli.py -h
```

1. Run attack surface discovery in an isolated virtual environment (Mock Mode):
```bash
python asm_cli.py scan --mock
```

2. Scan a real AWS account and save the JSON report:
```bash
python asm_cli.py scan --profile production-profile --output ./reports/asm_audit_report.json
```

---

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "Attack Surface Management: Continuously map and evaluate dynamic cloud exposure points.",
        "total_checks": 3,
        "failed_checks": 1
    },
    "findings": [
        {
            "service": "EC2",
            "resource": "sg-0123456789abcdef0",
            "surface_category": "Network Ingress",
            "check": "Unrestricted Internet Access (0.0.0.0/0)",
            "status": "FAIL"
        }
    ]
}
```
