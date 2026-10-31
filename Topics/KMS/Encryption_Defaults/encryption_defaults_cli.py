# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with S3 and EC2 (EBS).
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class EncryptionDefaultsAuditor:
    """
    (dev) Encryption Defaults Auditor class. Evaluates S3 default encryption settings
    and regional EBS account-level Encryption by Default status.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session, S3, and EC2 clients.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.s3 = session.client('s3', region_name='us-east-1')
        self.ec2 = session.client('ec2', region_name='us-east-1')

    def audit_encryption_defaults(self):
        """
        (dev) Audits storage encryption defaults:
        1. Enumerates S3 buckets and checks for default encryption rules.
        2. Checks regional EBS account-level Encryption by Default status.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        # --- 1. Audit S3 Bucket Default Encryption ---
        try:
            buckets = self.s3.list_buckets().get('Buckets', [])
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    enc_config = self.s3.get_bucket_encryption(Bucket=bucket_name)
                    rules = enc_config.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    if rules:
                        findings.append({
                            "resource_type": "S3 Bucket",
                            "resource_name": bucket_name,
                            "check": "S3 Default Encryption",
                            "status": "PASS",
                            "detail": f"Bucket has default encryption configured ({len(rules)} rule(s) active)."
                        })
                    else:
                        risk_count += 1
                        findings.append({
                            "resource_type": "S3 Bucket",
                            "resource_name": bucket_name,
                            "check": "S3 Default Encryption",
                            "status": "FAIL",
                            "detail": "Bucket encryption configuration has empty rules."
                        })
                except ClientError as ce:
                    error_code = ce.response.get('Error', {}).get('Code')
                    if error_code in ['ServerSideEncryptionConfigurationNotFoundError', 'NoSuchServerSideEncryptionConfiguration']:
                        risk_count += 1
                        findings.append({
                            "resource_type": "S3 Bucket",
                            "resource_name": bucket_name,
                            "check": "S3 Default Encryption",
                            "status": "FAIL",
                            "detail": "S3 bucket lacks active default encryption configuration."
                        })
                    else:
                        findings.append({
                            "resource_type": "S3 Bucket",
                            "resource_name": bucket_name,
                            "check": "S3 Default Encryption API Query",
                            "status": "ERROR",
                            "detail": str(ce)
                        })
        except Exception as e:
            findings.append({
                "resource_type": "S3 Service",
                "resource_name": "Bucket Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # --- 2. Audit EBS Account-Level Encryption by Default ---
        try:
            ebs_status = self.ec2.get_ebs_encryption_by_default()
            is_ebs_default = ebs_status.get('EbsEncryptionByDefault', False)

            if not is_ebs_default:
                risk_count += 1
                findings.append({
                    "resource_type": "EBS Account Settings",
                    "resource_name": "Regional EBS Settings",
                    "check": "EBS Encryption by Default",
                    "status": "FAIL",
                    "detail": "EBS Encryption by Default is DISABLED for this region. New volumes may be created unencrypted."
                })
            else:
                findings.append({
                    "resource_type": "EBS Account Settings",
                    "resource_name": "Regional EBS Settings",
                    "check": "EBS Encryption by Default",
                    "status": "PASS",
                    "detail": "EBS Encryption by Default is ENABLED for this region."
                })
        except Exception as e:
            findings.append({
                "resource_type": "EC2 / EBS Service",
                "resource_name": "EBS Encryption Status",
                "check": "API Query Execution",
                "status": "WARN",
                "detail": f"Could not verify EBS encryption by default (API restriction or mock limitation): {str(e)}"
            })

        report = {
            "metadata": {
                "philosophy": "Encryption Defaults: Eliminate human error by enforcing automatic encryption at rest across S3 and EBS, prioritizing auditable SSE-KMS for fintech compliance.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto environment with test scenarios:
    - A secure S3 bucket with default encryption.
    - An unencrypted legacy S3 bucket (Risk condition).
    """
    s3 = boto3.client('s3', region_name='us-east-1')
    ec2 = boto3.client('ec2', region_name='us-east-1')

    # 1. Secure bucket with default encryption
    s3.create_bucket(Bucket='secure-encrypted-bucket')
    s3.put_bucket_encryption(
        Bucket='secure-encrypted-bucket',
        ServerSideEncryptionConfiguration={
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123456789012:key/mock-key'
                }
            }]
        }
    )

    # 2. Insecure unencrypted bucket
    s3.create_bucket(Bucket='unencrypted-legacy-bucket')

    # 3. Enable EBS encryption by default in mock
    try:
        ec2.enable_ebs_encryption_by_default()
    except Exception:
        pass


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate S3 and EC2 locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs storage encryption defaults audits,
    handles file exports, and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Encryption-Defaults-Auditor: Audits S3 bucket encryption and EBS account defaults."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual storage encryption testbed...")
            setup_mock_environment()

        auditor = EncryptionDefaultsAuditor(profile=args.profile)
        report, risk_count = auditor.audit_encryption_defaults()

        json_output = json.dumps(report, indent=4)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Results successfully written to: {output_path.absolute()}")
        else:
            print(json_output)

        # --- PIPELINE EXIT CODE HANDLING ---
        if risk_count > 0:
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} unencrypted storage resource(s) / default gap(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on unencrypted storage
        else:
            print("\n[+] SUCCESS: Storage encryption defaults fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()