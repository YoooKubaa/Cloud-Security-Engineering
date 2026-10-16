# 🛡️ DiD-Auditor CLI (Defense in Depth Model)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**DiD-Auditor** is a Python-based CLI (Command Line Interface) tool designed to evaluate **Defense in Depth** implementations in an AWS environment. Instead of trusting a single security control, Defense in Depth relies on overlapping layers of defense (perimeter, resource, and data layers) to ensure that if one control fails, another stops the attack.

This tool audits critical AWS assets (such as S3 buckets) across multiple security tiers:
1. **Perimeter / Account Layer:** Account-level public access blocks.
2. **Resource Configuration Layer:** Bucket-level Block Public Access (BPA).
3. **Data Protection Layer:** Server-side encryption (SSE-KMS).

## ✨ Key Features

- **Multi-Layer Posture Scanning:** Validates whether resources are protected by a true defense-in-depth strategy rather than single points of failure.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` for full multi-layer compliance, `1` if defense layers are missing), integrating seamlessly into DevSecOps pipelines.
- **JSON Reporting:** Generates structured, machine-parsable JSON audit reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Features a `--mock` flag using `moto` to simulate fully defended and partially exposed S3 configurations in RAM safely.

## 🚀 Installation

1. Clone the repository and navigate to the project folder.
2. (Optional) Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install required dependencies:
```bash
pip install boto3 moto
```

---

## 🛠️ Usage
The tool uses standard library argparse for a robust command-line interface.
Display help menu:
```bash
python did_cli.py -h
```

1. Run multi-layer audit in an isolated virtual environment (Mock Mode):
```bash
python did_cli.py scan --mock
```

2. Scan a real AWS account and save the JSON report:
```bash
python did_cli.py scan --profile production-profile --output ./reports/did_audit_report.json
```

---

## 📊 Sample Output (JSON)
```bash
{
    "metadata": {
        "philosophy": "Defense in Depth: Multiple independent security controls protecting the same asset.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "service": "S3",
            "resource": "partially-exposed-bucket",
            "defense_layers_checked": 3,
            "layers_passed": 1,
            "status": "FAIL"
        }
    ]
}
```
