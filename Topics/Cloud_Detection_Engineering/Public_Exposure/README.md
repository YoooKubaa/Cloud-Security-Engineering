# 🌐 Public-Exposure-Detector CLI (Real-Time S3 & Security Group Exposure Detection)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![MITRE](https://img.shields.io/badge/MITRE_ATT&CK-T1530_/_T1190-red)

**Public-Exposure-Detector** is an automated Python CLI threat detection engine built to minimize the **exposure window**—the critical timeframe between a cloud resource becoming publicly accessible and security teams detecting it. 

Because accidental misconfigurations remain the #1 root cause of cloud data breaches, this tool inspects AWS CloudTrail API telemetry for real-time exposure mutations across both **Amazon S3** (ACLs, wildcard bucket policies, disabled Block Public Access) and **EC2 Security Groups** (`0.0.0.0/0` ingress rules on sensitive administrative and database ports).

## ✨ Key Features

- **Multi-Vector S3 Exposure Detection:** Catches `PutBucketAcl` (`public-read`/`public-read-write`), `PutBucketPolicy` (`Principal: "*"` without strict conditions), and `PutPublicAccessBlock` mutations setting protection flags to `False`.
- **High-Risk Security Group Ingress Inspection:** Parses `AuthorizeSecurityGroupIngress` parameters for `0.0.0.0/0` or `::/0` CIDR blocks, escalating severity to `CRITICAL` when administrative or database ports (`22`, `3389`, `3306`, `5432`) are exposed.
- **MITRE ATT&CK Enrichment:** Maps findings to `T1530` (Data from Cloud Storage) and `T1190` (Exploit Public-Facing Application) for rapid SOC triage.
- **CI/CD Ready (Pipeline Breaker):** Returns non-zero exit codes (`1`) whenever exposure events are detected.
- **Built-in Test Environment (Mocking):** Supports `--mock` mode to simulate realistic S3 and Security Group exposure events locally in RAM.

## 🚀 Installation

1. Navigate to the module folder.
2. Ensure dependencies are installed:
```bash
pip install boto3 moto
```

## 🛠️ Usage
Display help menu:
```bash
python public_exposure_detector_cli.py -h
```

1. Run the detector in mock mode (Simulated S3 & SG exposure events):
```bash
python public_exposure_detector_cli.py audit --mock
```

2. Audit a real AWS account and save the JSON report:
```bash
python public_exposure_detector_cli.py audit --profile production --output ./reports/public_exposure_audit.json
```

## 📊 Sample Output (JSON)

```json 
{
    "metadata": {
        "philosophy": "Public Exposure Detection: Minimize the exposure window by catching S3 public policy/ACL/BPA mutations and 0.0.0.0/0 Security Group ingress changes immediately in CloudTrail.",
        "total_checks": 3,
        "failed_checks": 3
    },
    "findings": [
        {
            "resource_type": "EC2 Security Group",
            "resource_name": "sg-0912837465abcdef0",
            "actor": "junior-devops",
            "event_name": "AuthorizeSecurityGroupIngress",
            "mitre_id": "T1190",
            "severity": "CRITICAL",
            "status": "FAIL",
            "detail": "CRITICAL EXPOSURE: Principal 'junior-devops' opened sensitive port(s) [22] to 0.0.0.0/0 on sg-0912837465abcdef0."
        }
    ]
}
```