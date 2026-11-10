# 🛡️ CSPM-Prowler-Triager CLI (Posture Management, Severity Scoring & Automated Triage)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![Prowler](https://img.shields.io/badge/Prowler-CSPM-brightgreen)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**CSPM-Prowler-Triager** is an advanced Python-based CLI tool designed to ingest, triage, and evaluate Cloud Security Posture Management (CSPM) scan results (specifically Prowler JSON reports). Recognizing that unmitigated alert fatigue ruins security programs, this tool applies rigorous triage logic (`Fix` vs. `Accept Risk` vs. `False Positive`), calculates risk based on exploitability and business impact, and enforces automated security gates in CI/CD pipelines.

## ✨ Key Features

- **Prowler Report Ingestion:** Parses standard Prowler JSON scan exports to evaluate AWS infrastructure configuration against benchmarks (CIS, PCI-DSS).
- **Intelligent Triage & Exception Handling:** Automatically filters findings against predefined risk acceptance rules (e.g., intentional public CDN buckets) to eliminate false alert fatigue.
- **Severity-Based Pipeline Gates:** Evaluates unmitigated CRITICAL and HIGH findings to determine whether deployment pipelines should pass or fail.
- **Structured JSON & Markdown Reporting:** Generates clean, actionable executive triage summaries for security audits.
- **Built-in Test Environment (Mocking):** Supports the `--mock` flag to simulate a realistic Prowler finding dataset locally in RAM for rapid testing.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3
```

## 🛠️ Usage
Display help menu:
```bash 
python cspm_triager_cli.py -h
```

1. Run the triager in mock mode (Simulated Prowler findings):
```bash 
python cspm_triager_cli.py triage --mock
```

2. Process a real Prowler JSON export and save the triage report:
```bash 
python cspm_triager_cli.py triage --report ./prowler-output.json --output ./reports/triage_summary.json
```

## 📊 Sample Output (JSON)
```json 
{
    "metadata": {
        "philosophy": "CSPM Triage: Separate static posture configuration misconfigurations from runtime behavior, applying intelligent exception governance (Fix vs Accept Risk).",
        "total_findings": 3,
        "actionable_failures": 1
    },
    "triage_results": [
        {
            "finding_id": "s3_bucket_public_access",
            "resource": "arn:aws:s3:::customer-data-vault",
            "severity": "CRITICAL",
            "decision": "FIX",
            "rationale": "Customer financial data bucket allows public read access. Immediate remediation required."
        }
    ]
}
```