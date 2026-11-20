# 🔄 KQL-to-AWS-Translator CLI (Multi-Cloud Detection Query Portability)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Multi-Cloud](https://img.shields.io/badge/Multi--Cloud-Azure_KQL_%E2%86%92_AWS-orange)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Detection_Portability-brightgreen)

**KQL-to-AWS-Translator** is a lightweight Python CLI tool designed to bridge multi-cloud SOC workflows by translating **Kusto Query Language (KQL)** detection logic (used in Microsoft Sentinel / Azure Monitor) into native **AWS CloudWatch Logs Insights** and **Amazon Athena (Presto SQL)** queries.

While maintaining an AWS-first detection engineering stack, security teams frequently adapt community analytics rules written in KQL. This utility parses pipe-delimited KQL pipelines (`where`, `project`, `summarize`, `count()`) and transpiles them into ready-to-run AWS telemetry queries.

---

## 📊 Multi-Cloud Query Dialect Reference (KQL vs. AWS)

| Operacja | Microsoft Sentinel (KQL) | AWS CloudWatch Logs Insights | Amazon Athena (Presto SQL) |
| :--- | :--- | :--- | :--- |
| **Źródło danych** | `SigninLogs` / `AWSCloudTrail` | Wybrany `Log Group` | `SELECT * FROM cloudtrail_logs` |
| **Filtrowanie** | `\| where ResultType != "0"` | `\| filter eventName = "ConsoleLogin"` | `WHERE eventname = 'ConsoleLogin'` |
| **Wybór kolumn** | `\| project User, IPAddress` | `\| fields @timestamp, userIdentity.arn` | `SELECT useridentity.arn, sourceipaddress` |
| **Agregacja** | `\| summarize count() by User` | `\| stats count() by userIdentity.arn` | `GROUP BY useridentity.arn` |
| **Próg (Threshold)** | `\| where FailedAttempts > 5` | `\| filter count > 5` | `HAVING COUNT(*) > 5` |

---

## ✨ Key Features

- **Pipe-to-AWS Transpilation:** Parses KQL pipeline stages (`| where`, `| project`, `| summarize count() by ...`) and maps operators (`==`, `!=`, `>`) into CloudWatch Logs Insights and Athena SQL syntax.
- **Schema Field Mapping:** Translates common identity and cloud event fields (`UserPrincipalName`, `IPAddress`, `ResultType`) into AWS CloudTrail equivalents (`userIdentity.arn`, `sourceIPAddress`, `errorCode`).
- **Threshold & Aggregation Support:** Converts KQL `summarize ... by ... | where count > N` brute-force detection patterns into SQL `GROUP BY ... HAVING` and CloudWatch `stats ... | filter` clauses.
- **Built-in Test Environment (Mocking):** Supports `--mock` mode with a realistic KQL brute-force detection query for instant local demonstration.

## 🚀 Installation

1. Navigate to the module folder.
2. No external dependencies required (uses Python 3.9+ standard library: `argparse`, `json`, `re`, `pathlib`).

## 🛠️ Usage
Display help menu:
```bash
python kql_translator_cli.py -h
```

1. Run in mock mode (Translates a built-in KQL brute-force rule into CloudWatch & Athena):
```bash
python kql_translator_cli.py translate --mock
```

2. Translate a custom KQL query string and save the JSON output:
```bash
python kql_translator_cli.py translate --query 'AWSCloudTrail | where EventName == "ConsoleLogin" | where ErrorCode != "0" | summarize FailedAttempts=count() by UserIdentityArn, SourceIPAddress | where FailedAttempts > 5' --output ./reports/kql_translation.json
```

## 📊 Sample Output (JSON)

```json
{
    "metadata": {
        "philosophy": "Multi-Cloud Detection Portability: Translate Azure Sentinel KQL pipe queries into AWS CloudWatch Logs Insights and Athena SQL to reuse cross-platform threat hunting logic.",
        "source_dialect": "KQL (Kusto Query Language)",
        "target_dialects": ["AWS CloudWatch Logs Insights", "Amazon Athena SQL"]
    },
    "translation": {
        "original_kql": "SigninLogs | where ResultType != \"0\" | summarize FailedAttempts=count() by UserPrincipalName, IPAddress | where FailedAttempts > 5",
        "cloudwatch_logs_insights": "fields @timestamp, userIdentity.arn, sourceIPAddress | filter errorCode != '0' | stats count(*) as FailedAttempts by userIdentity.arn, sourceIPAddress | filter FailedAttempts > 5",
        "amazon_athena_sql": "SELECT useridentity.arn, sourceipaddress, COUNT(*) AS FailedAttempts FROM cloudtrail_logs WHERE errorcode != '0' GROUP BY useridentity.arn, sourceipaddress HAVING COUNT(*) > 5;"
    }
}
```