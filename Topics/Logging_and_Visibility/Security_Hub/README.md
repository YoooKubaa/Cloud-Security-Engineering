# 🌐 Security-Hub-Auditor CLI (Meta-CSPM Findings Aggregation & Compliance Governance)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**Security-Hub-Auditor** is an advanced Python-based CLI tool designed to audit AWS Security Hub enablement, active security standards (CIS, AWS Foundational Security Best Practices, PCI-DSS), and multi-source findings aggregation. Recognizing that Security Hub serves as the central orchestration point for native tools, third-party CSPM scanners (Prowler), and custom Python threat detections, this tool verifies compliance postures and ensures telemetry aggregation pipelines are active across cloud environments.

## ✨ Key Features

- **Security Hub Enablement Audit:** Verifies that Security Hub is active and properly provisioned within the target AWS account and region.
- **Standards & Compliance Inspection:** Audits enabled security standard subscriptions (e.g., CIS AWS Foundations Benchmark, AWS Foundational Best Practices).
- **Findings Aggregation Governance:** Ensures disparate security telemetry streams feed into a unified dashboard for automated incident response.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if Security Hub posture is fully compliant, `1` if Security Hub is disabled or missing baseline standards).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate Security Hub instances and standards locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

##🛠️ Usage
Display help menu:
```bash
python security_hub_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python security_hub_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python security_hub_auditor_cli.py audit --profile production --output ./reports/securityhub_audit.json
```

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "Security Hub Aggregation: Centralize findings from native tools, third-party CSPM (Prowler), and custom detections into a single compliance and incident dashboard.",
        "total_checks": 2,
        "failed_checks": 0
    },
    "findings": [
        {
            "resource_type": "Security Hub",
            "resource_name": "Account Security Hub",
            "check": "Security Hub Enablement",
            "status": "PASS",
            "detail": "AWS Security Hub is enabled and operational."
        }
    ]
}
```