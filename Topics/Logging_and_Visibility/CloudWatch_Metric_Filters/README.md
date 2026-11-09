# 🚨 CloudWatch-Metric-Filters-Auditor CLI (Native Real-Time Threat Detection & Alarms)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**CloudWatch-Metric-Filters-Auditor** is an advanced Python-based CLI tool designed to audit native AWS real-time detection pipelines. Recognizing that basic security alerts (such as console logins without MFA, IAM privilege escalation via `AdministratorAccess`, and CloudTrail disabling) must be established before adopting heavy SIEM solutions, this tool verifies that critical metric filters and associated CloudWatch alarms are actively configured and bound to notification channels.

## ✨ Key Features

- **Security Metric Filter Audit:** Scans CloudWatch log groups for critical security filter patterns (e.g., `ConsoleLoginNoMFA`, `AdminPolicyAttach`, `StopLogging`).
- **Alarm Integration Verification:** Ensures every critical security metric filter has a corresponding CloudWatch alarm linked to an SNS topic for immediate incident notification.
- **Threat Baseline Enforcement:** Enforces mandatory detection baselines required by enterprise security frameworks (SOC2, PCI-DSS).
- **CI/CD Ready (Pipeline Breaker):** Returns appropriate exit codes (`0` if all mandatory security filters and alarms exist, `1` if detection gaps are detected).
- **JSON Reporting:** Generates structured, machine-parsable audit telemetry reports using native `json` and `pathlib` libraries.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag using the `moto` library to simulate security metric filters and alarms locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash 
python cloudwatch_filters_auditor_cli.py -h
```

1. Run the auditor in mock mode (Isolated RAM environment):
```bash 
python cloudwatch_filters_auditor_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash 
python cloudwatch_filters_auditor_cli.py audit --log-group /cloudtrail/prod --profile production --output ./reports/cw_filters_audit.json
```

## 📊 Sample Output (JSON)

```json 
{
    "metadata": {
        "philosophy": "CloudWatch Metric Filters: Build native real-time threat detection by mapping CloudTrail JSON patterns to metrics and SNS alarms for instant incident notification.",
        "total_checks": 3,
        "failed_checks": 1
    },
    "findings": [
        {
            "resource_type": "CloudWatch Metric Filter",
            "resource_name": "ConsoleLoginNoMFA",
            "check": "Metric Filter & Alarm Binding",
            "status": "PASS",
            "detail": "Metric filter 'ConsoleLoginNoMFA' is active and linked to an alarm."
        }
    ]
}
```