# 🎛️ Detection-Tuning-Engine CLI (False Positive Governance & Alert Fatigue Prevention)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Detection_Tuning-brightgreen)
![SOC](https://img.shields.io/badge/SOC-Zero_Alert_Fatigue-blue)

**Detection-Tuning-Engine** is a Python-based CLI tool designed to eliminate **alert fatigue** while preventing blind spots (**false negatives**) in cloud threat detection pipelines. 

In real-world SOC operations, raw detection rules frequently trigger on authorized automation (such as CI/CD pipelines rotating IAM access keys or Terraform provisioning infrastructure). Simply disabling noisy rules destroys visibility, while undocumented whitelists create unmonitored security gaps. This tool enforces **documented allowlist governance**—requiring explicit business rationale, rule narrowing conditions, and expiration/review dates for every suppressed alert.

---

## 📋 Detection Tuning Log (Governance Deliverable)

| Date | Rule Name | Observed False Positive | Root Cause / Rationale | Tuning Action | Risk Trade-off |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-11-21` | `IAM-CreateAccessKey` | `arn:aws:iam::123456789012:role/github-actions-rotator` triggers alerts on scheduled key rotation | Authorized CI/CD credential rotation workflow | Narrow rule via ARN allowlist (`TUNE-001`) | Low — scoped strictly to single CI/CD role ARN |
| `2026-11-21` | `IAM-AttachPolicy` | `terraform-deploy-role` attaches `ReadOnlyAccess` during stack builds | Routine IaC deployment of non-privileged read policies | Narrow condition to alert only on `*AdministratorAccess*` or `*PowerUser*` (`TUNE-002`) | Low — privilege escalation paths remain monitored |

---

## ✨ Key Features

- **Documented Allowlist Governance:** Enforces structured tuning rules (`id`, `event_name`, `principal_arn`, `rationale`, `approved_by`) before suppressing any alert.
- **Condition Narrowing & Threshold Evaluation:** Filters benign high-privilege-looking actions when scoped to non-admin policies or verified automation principals, while escalating deviations immediately.
- **Signal-to-Noise Ratio Metrics:** Calculates noise reduction percentages and separates `ACTIONABLE_ALERT` findings from `SUPPRESSED_FP` events.
- **CI/CD Ready (Pipeline Breaker):** Exits with code `1` only when genuine, un-tuned threats remain, allowing authorized automation to pass cleanly (`0`).
- **Built-in Test Environment (Mocking):** Supports `--mock` mode with realistic CI/CD noise mixed with genuine attacker behavior for instant demonstration.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure `boto3` is installed (optional for live CloudTrail queries; `--mock` runs with standard Python 3.9+):
```bash
pip install boto3
```

## 🛠️ Usage
Display help menu:
```bash
python tuning_engine_cli.py -h
```

1. Run in mock mode (Evaluates mixed CI/CD noise + attacker events against documented tuning rules):
```bash
python tuning_engine_cli.py evaluate --mock
```

2. Evaluate events using a custom tuning allowlist file and export JSON report:
```bash
python tuning_engine_cli.py evaluate --allowlist ./tuning_rules.json --output ./reports/tuned_alerts.json
```

## 📊 Sample Output (JSON)
```json
{
    "metadata": {
        "philosophy": "Detection Tuning & False Positive Governance: Never blindly disable noisy rules. Narrow conditions, document every allowlist exception with business rationale, and preserve visibility against false negatives.",
        "total_events_analyzed": 3,
        "suppressed_false_positives": 2,
        "actionable_alerts": 1,
        "noise_reduction_percent": 66.7
    },
    "actionable_findings": [
        {
            "event_name": "CreateAccessKey",
            "principal": "arn:aws:iam::123456789012:user/compromised-analyst",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": "UNTUNED ALERT: Principal 'arn:aws:iam::123456789012:user/compromised-analyst' executed 'CreateAccessKey' outside documented automation baselines."
        }
    ]
}
```