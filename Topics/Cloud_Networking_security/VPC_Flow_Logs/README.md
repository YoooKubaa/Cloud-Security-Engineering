# 📡 VPC-Flow-Logs-Auditor CLI (Network Traffic Monitoring & Lateral Movement Defense)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**VPC-Flow-Logs-Auditor** is an advanced Python-based CLI tool designed to audit network telemetry coverage across AWS Virtual Private Clouds (VPCs). Recognizing that VPC Flow Logs are the sole mechanism for capturing network packet metadata (traffic actions like `ACCEPT` and `REJECT`) to detect Lateral Movement and unauthorized scans, this tool verifies that all active VPCs enforce continuous logging destinations (CloudWatch Logs or S3).

## ✨ Key Features

- **VPC Telemetry Coverage Audit:** Scans all active VPCs to verify if Flow Logs are enabled, preventing "blind spots" in network forensic monitoring.
- **Traffic Type Verification:** Ensures flow logs capture comprehensive traffic (`ALL`, or at least `REJECT` records crucial for security analysis).
- **Compliance & Forensics Enforcement:** Enforces strict logging baselines required by enterprise security standards (SOC2, ISO 27001, PCI-DSS).
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if all VPCs have flow logs active, `1` if unmonitored VPCs are detected).
- **JSON Reporting:** Generated structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate monitored and unmonitored VPC topologies locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python vpc_flow_logs_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python vpc_flow_logs_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python vpc_flow_logs_auditor_cli.py audit --profile production --output ./reports/flow_logs_audit.json
```

## 📊 Sample Output (JSON)

```json 
{
    "metadata": {
        "philosophy": "VPC Flow Logs: Capture network traffic metadata (ACCEPT/REJECT) across VPCs to detect lateral movement, unauthorized port scans, and security anomalies.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "VPC",
            "resource_name": "vpc-unmonitored-mock",
            "check": "VPC Flow Logs Active",
            "status": "FAIL",
            "detail": "VPC does not have VPC Flow Logs enabled. Network traffic is unmonitored."
        }
    ]
}
```