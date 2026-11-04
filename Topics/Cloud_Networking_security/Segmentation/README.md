# 🚷 Network-Segmentation-Auditor CLI (Zero Trust & Blast Radius Governance)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**Network-Segmentation-Auditor** is an advanced Python-based CLI tool designed to audit network segmentation and workload placement postures across AWS VPCs. Recognizing that perimeter defense and lateral movement prevention require strict isolation, this tool maps subnets to Internet Gateways, identifies misconfigured workloads (such as application or database servers running in public subnets), and enforces Zero Trust microsegmentation principles.

## ✨ Key Features

- **Workload Placement Audit:** Scans EC2 instances running within public subnets (subnets with active Internet Gateway routes) to detect unauthorized application or database server exposures.
- **Blast Radius Reduction:** Enforces private-first architectures where only ingress components (ALB/NAT Gateways) reside in public tiers, keeping internal logic strictly isolated.
- **Microsegmentation Verification:** Evaluates Security Group isolation boundaries to prevent flat, unsegmented network anti-patterns.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if segmentation posture is secure, `1` if workloads are improperly exposed in public subnets).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate compliant and non-compliant workload placements locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash 
python segmentation_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash 
python segmentation_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash 
python segmentation_auditor_cli.py audit --profile production --output ./reports/segmentation_audit.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "Network Segmentation: Enforce Zero Trust by isolating workloads into private tiers, keeping public subnets strictly for ALBs and NAT gateways to eliminate lateral movement.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "EC2 Instance",
            "resource_name": "i-0abcdef1234567890 (AppServer)",
            "check": "Public Subnet Workload Exposure",
            "status": "FAIL",
            "detail": "Application or database workload instance is running inside a public subnet (routed to an Internet Gateway). Workloads must reside in private subnets."
        }
    ]
}
```