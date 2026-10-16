# 🏛️ Cloud Security Frameworks & Core Models Portfolio

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![AWS SDK](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Pipeline_Gates-brightgreen)
![Testing](https://img.shields.io/badge/Moto-In_Memory_Mocking-lightgrey)

Welcome to the **Cloud Security Frameworks & Core Models** portfolio directory. This repository contains a suite of production-grade, automated Command Line Interface (CLI) tools and threat mapping engines designed to bridge cloud security theory with executable, code-driven enforcement.

Rather than treating cloud security models as abstract documentation, this project implements them as **DevSecOps security gates**—programmable checks that evaluate, audit, and validate infrastructure compliance against real-world threat models.

---

## 🏗️ Architecture & Component Overview

The portfolio is structured around six core security paradigms, each implemented as an independent, modular CLI utility featuring in-memory mocking (`moto`) and CI/CD pipeline-breaking exit codes (`0` for success, `1` for violation).

| Tool / Directory | Core Security Model / Framework | Primary Objective | Key AWS / Python Tech |
| :--- | :--- | :--- | :--- |
| **`SRM-Auditor`** | **Shared Responsibility Model** | Audits customer-side configuration boundaries ("IN the cloud") like S3 BPA and EC2 public SSH exposure. | `boto3`, `argparse`, `pathlib`, `moto` |
| **`ZT-Auditor`** | **Zero Trust Model** | Enforces "Never Trust, Always Verify" by checking IMDSv2 metadata protection and network microsegmentation. | `boto3`, `argparse`, `pathlib`, `moto` |
| **`DiD-Auditor`** | **Defense in Depth** | Evaluates multi-layer asset protection across perimeter, resource, and data encryption tiers (SSE-KMS). | `boto3`, `argparse`, `pathlib`, `moto` |
| **`CKC-Auditor`** | **Cloud Kill Chain** | Detects early-stage threat enablers like disabled audit logging (Defense Evasion) and risky IAM access keys. | `boto3`, `argparse`, `pathlib`, `moto` |
| **`ASM-Auditor`** | **Attack Surface Management** | Continuously maps dynamic cloud exposure points across network, storage, and identity surfaces. | `boto3`, `argparse`, `pathlib`, `moto` |
| **`CAM-Mapper`** | **MITRE ATT&CK for Cloud** | Translates raw cloud log events (CloudTrail) into standardized adversary tactics and technique IDs. | Pure Python (`argparse`, `json`, `pathlib`) |

---

## 🚀 Common Execution & Testing Philosophy

All tools in this portfolio share a standardized developer experience and operational design:

1. **Local-First Testing (Zero Cost):** Leveraging the `moto` library to spin up fully isolated virtual AWS environments in RAM. No live cloud account required for testing.
2. **Standardized CLI Interface:** Built using Python's native `argparse` library with predictable flags (`--mock`, `--profile`, `--output`).
3. **Pipeline Integration (Fail Fast):** Designed to act as automated security gates in CI/CD pipelines, returning non-zero exit codes (`sys.exit(1)`) when vulnerabilities or risk patterns are discovered.

### Quick Start Example (Mock Mode)
You can run any auditor instantly without cloud credentials:
```bash
# Example: Running the Defense in Depth auditor in mock mode
cd Defense_in_Depth/
python did_cli.py scan --mock
```
