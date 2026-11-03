# 🔌 VPC-Endpoint-Auditor CLI (PrivateLink & Private AWS API Governance)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**VPC-Endpoint-Auditor** is an advanced Python-based CLI tool designed to audit AWS VPC Endpoints (PrivateLink) and verify that internal workloads communicate with AWS services (S3, KMS, DynamoDB, Secrets Manager) entirely within the private AWS backbone without traversing the public internet or requiring NAT Gateways.

## ✨ Key Features

- **VPC Endpoint Inventory:** Scans and inventories active VPC endpoints, categorizing them into Gateway Endpoints (S3/DynamoDB) and Interface Endpoints (PrivateLink ENIs).
- **Endpoint Policy Validation:** Inspects attached VPC endpoint resource-based policies to detect over-permissive access statements (e.g., wildcard principals allowing unconstrained service access).
- **Perimeter & Compliance Enforcement:** Ensures strict alignment with regulatory requirements (PCI-DSS, SOC2) by validating private-only data pathways.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if private endpoint posture is secure, `1` if insecure endpoint policies or missing private routing configurations are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate VPC endpoints and resource policies locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python privatelink_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python privatelink_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python privatelink_auditor_cli.py audit --profile production --output ./reports/privatelink_audit.json
```

## 📊 Sample Output (JSON)

```json 
{
    "metadata": {
        "philosophy": "PrivateLink & Endpoints: Route internal AWS API traffic securely via private endpoints (Gateway vs Interface), eliminating NAT Gateway exposure and public internet transit.",
        "total_checks": 2,
        "failed_checks": 0
    },
    "findings": [
        {
            "resource_type": "VPC Endpoint",
            "resource_name": "vpce-mock-s3-gateway",
            "check": "Gateway Endpoint Configuration",
            "status": "PASS",
            "detail": "Gateway endpoint for S3 is active, providing secure private routing without NAT."
        }
    ]
}
```