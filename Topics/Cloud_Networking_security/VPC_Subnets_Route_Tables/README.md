# 🌐 VPC-Topology-Auditor CLI (Subnet Segmentation & Route Table Governance)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**VPC-Topology-Auditor** is an advanced Python-based CLI tool designed to audit AWS Virtual Private Cloud (VPC) architectures, subnet segmentations, and Route Table associations. Recognizing that network security boundaries are defined by routing rules rather than subnet names, this tool inspects route tables for direct Internet Gateway (`IGW`) exposures, verifies private isolation, and prevents accidental public exposure of internal workloads.

## ✨ Key Features

- **Route Table Association Audit:** Maps subnets to their effective Route Tables to accurately evaluate public vs. private isolation status.
- **Internet Gateway (IGW) Exposure Detection:** Scans route tables for default routes (`0.0.0.0/0`) pointing to Internet Gateways, identifying unintended public subnets.
- **Network Perimeter Governance:** Ensures proper architectural segregation between public facing tiers and private/isolated database workloads.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if network topology is compliant, `1` if unauthorized public routing or misconfigurations are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate complex VPC, subnet, IGW, and route table topologies locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python vpc_topology_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python vpc_topology_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python vpc_topology_auditor_cli.py audit --profile production --output ./reports/vpc_topology_audit.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "VPC Topology: Subnets are not inherently public or private; Route Tables dictate traffic routing via Internet Gateways or NAT Gateways.",
        "total_checks": 2,
        "failed_checks": 0
    },
    "findings": [
        {
            "resource_type": "VPC Route Table",
            "resource_name": "rtb-public-mock",
            "check": "Internet Gateway Route Exposure",
            "status": "PASS",
            "detail": "Route table correctly routes 0.0.0.0/0 to an Internet Gateway (Public Subnet configuration)."
        }
    ]
}
```