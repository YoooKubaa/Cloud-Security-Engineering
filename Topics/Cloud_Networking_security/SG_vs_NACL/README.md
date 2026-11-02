# 🔒 SG-NACL-Auditor CLI (Stateful Instance Firewalls vs Stateless Subnet Guardrails)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**SG-NACL-Auditor** is an advanced Python-based CLI tool designed to audit network firewall configurations across AWS Security Groups (stateful instance-level firewalls) and Network ACLs (stateless subnet-level guardrails). Recognizing that 95% of perimeter security relies on Security Groups, this tool scans ingress rules for dangerous open ports (`0.0.0.0/0` on SSH, RDP, or databases) and evaluates NACL rule evaluations to prevent exposure anti-patterns.

## ✨ Key Features

- **Security Group Ingress Audit:** Inventories security groups and flags over-permissive ingress rules allowing unrestricted access (`0.0.0.0/0`) to high-risk administrative or database ports (e.g., port 22, 3389, 3306, 5432).
- **Stateless NACL Rule Inspection:** Inspects Network ACL entries to verify subnet traffic boundaries and detect overly permissive stateless configurations.
- **Firewall Hygiene Enforcement:** Ensures that stateful instance firewalls adhere to strict least-privilege principles, avoiding wide-open CIDR blocks.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if firewall posture is secure, `1` if dangerous open ports or risky exposure rules are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate secure and misconfigured firewall states locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python sg_nacl_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python sg_nacl_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python sg_nacl_auditor_cli.py audit --profile production --output ./reports/firewall_audit.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "SG vs NACL: Security Groups are stateful firewalls protecting individual ENIs (used 95% of the time), while NACLs are stateless subnet firewalls supporting explicit deny rules.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "Security Group",
            "resource_name": "sg-insecure-mock",
            "check": "Over-permissive Ingress (SSH Port 22)",
            "status": "FAIL",
            "detail": "Security Group allows unrestricted inbound traffic (0.0.0.0/0) on sensitive administrative port 22."
        }
    ]
}
```