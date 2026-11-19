# 📜 Sigma-Cloud-Evaluator CLI (Detection-as-Code, Rule Validation & Backend Transpilation)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![YAML](https://img.shields.io/badge/Sigma-YAML_Rules-informational)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Detection_as_Code-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE_ATT&CK-Mapped-red)

**Sigma-Cloud-Evaluator** is a Python-based CLI tool designed to operationalize **Detection-as-Code (DaC)** workflows using the open-source **Sigma** rule specification. Rather than locking detection logic inside proprietary SIEM query languages, Sigma allows security engineers to define backend-agnostic detection rules once in YAML and deploy them across Splunk, Elastic, Sentinel, or native AWS log pipelines.

This tool validates Sigma rule schemas, enforces MITRE ATT&CK tagging standards, transpiles rules into native **AWS CloudWatch Logs Insights** and **Splunk SPL** queries, and evaluates CloudTrail JSON events directly against Sigma `detection` blocks.

## ✨ Key Features

- **Sigma Schema & Quality Gate:** Validates required YAML fields (`title`, `id`, `logsource`, `detection`, `level`) and checks for mandatory `attack.*` MITRE ATT&CK tags.
- **Multi-Backend Query Transpilation:** Converts Sigma `detection` selections into ready-to-use **AWS CloudWatch Logs Insights** and **Splunk SPL** queries without requiring a full SIEM deployment.
- **Local CloudTrail Evaluation Engine:** Evaluates CloudTrail JSON telemetry directly against Sigma rule conditions in memory.
- **CI/CD Ready (Pipeline Breaker):** Returns non-zero exit codes (`1`) if a Sigma rule fails schema validation or triggers a high/critical alert during log evaluation.
- **Built-in Test Environment (Mocking):** Supports `--mock` mode with embedded Sigma rules and simulated CloudTrail events for zero-dependency execution.

## 🚀 Installation

1. Navigate to the module folder.
2. Install `PyYAML` (standard library handles `json`, `argparse`, `pathlib`):
```bash
pip install pyyaml
```

## 🛠️ Usage
Display help menu:
```bash
python sigma_evaluator_cli.py -h
```

1. Run in mock mode (Validates built-in Sigma rule, generates SIEM queries, and tests against mock CloudTrail logs):
```bash
python sigma_evaluator_cli.py evaluate --mock
```

2. Validate and transpile a custom Sigma YAML rule file:
```bash
python sigma_evaluator_cli.py evaluate --rule ./rules/aws_cloudtrail_stoplogging.yml --output ./reports/sigma_eval.json
```

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "Detection-as-Code with Sigma: Write backend-agnostic YAML detection logic once, enforce MITRE ATT&CK metadata, and transpile across cloud log backends.",
        "rule_title": "AWS CloudTrail Logging Disabled or Deleted",
        "severity": "critical",
        "matched_events": 1
    },
    "transpiled_queries": {
        "cloudwatch_logs_insights": "fields @timestamp, eventName, userIdentity.arn, sourceIPAddress | filter eventName in ['StopLogging', 'DeleteTrail']",
        "splunk_spl": "index=aws_cloudtrail (eventName=\"StopLogging\" OR eventName=\"DeleteTrail\")"
    }
}
```