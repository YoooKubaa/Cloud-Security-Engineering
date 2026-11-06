# 🛡️ WAF-Tuning-Auditor CLI (Web ACL Rule Governance & False Positive Management)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**WAF-Tuning-Auditor** is an advanced Python-based CLI tool designed to audit AWS WAF Web ACL configurations, rule priorities, and enforcement modes (`COUNT` vs `BLOCK`). Recognizing that deploying managed rule groups directly in blocking mode risks catastrophic false positives, this tool evaluates Web ACL hygiene, verifies metric logging configurations, and ensures safe rule tuning lifecycles across edge gateways (ALB, API Gateway, CloudFront).

## ✨ Key Features

- **Web ACL Rule Inspection:** Inventories Web ACLs and inspects individual managed and custom rule groups.
- **Enforcement Mode Audit:** Detects whether newly introduced or high-impact rules are safely staged in `COUNT` mode (logging hits without disrupting traffic) or actively enforcing `BLOCK` mode.
- **Telemetry & Visibility Verification:** Ensures CloudWatch metrics and request sampling are enabled for effective false-positive analysis.
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if Web ACL posture is compliant, `1` if unmonitored rules or unsafe block configurations are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate Web ACL rule sets locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python waf_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash
python waf_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python waf_auditor_cli.py audit --scope REGIONAL --profile production --output ./reports/waf_audit.json
```

## 📊 Sample Output (JSON)

```json 
{
    "metadata": {
        "philosophy": "AWS WAF Tuning: Safely tune managed and custom rule groups using COUNT mode before enforcement to eliminate false positives without creating security blind spots.",
        "total_checks": 2,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "AWS WAF Rule",
            "resource_name": "AWSManagedRulesCommonRuleSet",
            "check": "Rule Enforcement Mode",
            "status": "WARN",
            "detail": "Managed rule group is operating in COUNT override mode. Ensure false positive analysis is completed before promoting to BLOCK."
        }
    ]
}
```