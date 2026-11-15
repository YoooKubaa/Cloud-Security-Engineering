# 🕵️ IAM-Abuse-Detector CLI (Privilege Escalation & Persistence Threat Detection)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**IAM-Abuse-Detector** is an advanced Python-based CLI tool designed to analyze AWS CloudTrail event telemetry and detect sophisticated IAM abuse patterns, such as Privilege Escalation (`iam:PassRole` combined with `lambda:CreateFunction` or `ec2:RunInstances`) and unauthorized Persistence mechanisms (`CreateAccessKey`).

## ✨ Key Features

- **Temporal Correlation Analysis:** Detects high-risk multi-step attack chains where administrative IAM permissions are chained within tight time windows.
- **Persistence Detection:** Identifies anomalous creation of new access keys for existing users, establishing baseline deviations.
- **MFA-less Console Login Monitoring:** Flags administrative console logins lacking Multi-Factor Authentication.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if audit telemetry is clean, `1` if IAM abuse or privilege escalation indicators are detected).
- **JSON Reporting:** Generates structured, machine-parsable security telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate malicious IAM abuse event logs locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

##🛠️ Usage
Display help menu:
```bash
python iam_abuse_detector_cli.py -h
```

1. Run the detector in mock mode (Isolated RAM environment):
```bash
python iam_abuse_detector_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python iam_abuse_detector_cli.py audit --profile production --output ./reports/iam_abuse_audit.json
```

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "IAM Abuse Detection: Correlate sequential CloudTrail API events (e.g., PassRole + CreateFunction) in tight time windows to catch privilege escalation before exploitation.",
        "total_checks": 3,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "IAM Principal",
            "resource_name": "arn:aws:iam::123456789012:user/compromised-actor",
            "check": "Privilege Escalation Chain (PassRole + CreateFunction)",
            "status": "FAIL",
            "detail": "Detected suspicious temporal correlation: 'PassRole' followed by 'CreateFunction' within 5 minutes by the same principal."
        }
    ]
}
```