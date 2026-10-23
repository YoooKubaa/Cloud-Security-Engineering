# 🌐 Federation-Auditor CLI (OIDC, SAML & Trust Conditions)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**Federation-Auditor** is a Python-based CLI tool designed to audit Identity Federation and Single Sign-On (SSO) trust relationships in AWS environments. Focusing heavily on modern **OIDC (OpenID Connect)** and **SAML 2.0** integrations, this tool inspects IAM OpenID Connect providers and IAM Role trust policies to ensure strict boundary conditions (`Condition` blocks) prevent unauthorized cross-repository or cross-tenant assumption.

## ✨ Key Features

- **OIDC Provider Inventory:** Discovers and audits registered Web Identity Providers (such as GitHub Actions OIDC).
- **Trust Condition Validation:** Inspects `AssumeRoleWithWebIdentity` trust policies for missing or weak `Condition` scopes (e.g., verifying `token.actions.githubusercontent.com:sub`).
- **Elimination of Long-term Credentials:** Enforces temporary STS tokens over native IAM user access keys for human and machine workloads alike.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if secure, `1` if insecure trust relationships are detected) to block vulnerable CI/CD pipelines.
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate secure and vulnerable OIDC trust configurations locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash 
python federation_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash 
python federation_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python federation_auditor_cli.py audit --profile production --output ./reports/federation_audit.json
```

## 📊 Sample Output (JSON)

```json 
{
    "metadata": {
        "philosophy": "Federation & SSO: Centralize identity management via IdPs and enforce strict Condition scopes on OIDC/SAML trust policies.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "IAM Role (OIDC Trust)",
            "resource_name": "InsecurePipelineRole",
            "check": "OIDC Trust Policy Condition Scope",
            "status": "FAIL",
            "detail": "OIDC trust policy allows AssumeRoleWithWebIdentity without a strict Condition block (missing repository/branch restriction)."
        }
    ]
}
```