# 🛡️ SRM-Auditor CLI (Shared Responsibility Model)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**SRM-Auditor** is a Python-based CLI (Command Line Interface) tool that verifies compliance with the **Shared Responsibility Model** in an AWS account. It focuses exclusively on the customer's responsibility layer, which is security **"IN the cloud"** (service configuration, data protection, and the network layer).

Instead of theorizing about responsibility boundaries, this tool practically audits configuration oversights on the customer's side that could lead to data leaks (e.g., missing S3 Block Public Access) or environment compromise (e.g., an SSH port open to the world).

## ✨ Key Features

- **Resource Scanning (S3, EC2):** Verifies critical touchpoints on the AWS-Customer boundary.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` for success, `1` if vulnerabilities are found), allowing you to block deployments in DevSecOps pipelines.
- **JSON Reporting:** Generates a structured, easy-to-parse (e.g., via `jq`) results file using the native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag, which utilizes the `moto` library to generate virtual, isolated infrastructure in RAM. This allows for safe testing without the risk of incurring costs or impacting a real AWS environment.

## 🚀 Installation

1. Clone the repository and navigate to the project directory.
2. (Optional) Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install the required packages:
```bash
pip install boto3 moto
```
