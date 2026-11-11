# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with S3.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class S3ImmutabilityAuditor:
    """
    (dev) S3 Immutability Auditor class. Evaluates log storage buckets
    for S3 Object Lock and Versioning configuration to guarantee tamper-proof forensics.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and S3 client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.s3 = session.client('s3', region_name='us-east-1')

    def audit_immutability(self):
        """
        (dev) Audits S3 log bucket immutability:
        1. Enumerates S3 buckets (specifically targeting log buckets based on naming convention or checks all).
        2. Checks if bucket versioning is enabled.
        3. Checks if S3 Object Lock is enabled.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            buckets = self.s3.list_buckets().get('Buckets', [])
            
            if not buckets:
                findings.append({
                    "resource_type": "S3 Service",
                    "resource_name": "Account Buckets",
                    "check": "Bucket Enumeration",
                    "status": "PASS",
                    "detail": "No S3 buckets found in account."
                })
            else:
                for bucket in buckets:
                    bucket_name = bucket['Name']
                    
                    # Heuristic: Focus audit primarily on buckets containing 'log', 'trail', or 'audit'
                    is_log_bucket = any(kw in bucket_name.lower() for kw in ['log', 'trail', 'audit', 'telemetry'])

                    if not is_log_bucket:
                        # Skip general purpose buckets or note them as non-log
                        continue

                    # 1. Check Versioning
                    try:
                        Versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                        status = Versioning.get('Status', '')
                        if status != 'Enabled':
                            risk_count += 1
                            findings.append({
                                "resource_type": "S3 Bucket",
                                "resource_name": bucket_name,
                                "check": "Bucket Versioning Enabled",
                                "status": "FAIL",
                                "detail": f"Log bucket versioning is '{status}' (not Enabled). Versioning is required for Object Lock."
                            })
                        else:
                            findings.append({
                                "resource_type": "S3 Bucket",
                                "resource_name": bucket_name,
                                "check": "Bucket Versioning Enabled",
                                "status": "PASS",
                                "detail": "Log bucket versioning is enabled."
                            })
                    except ClientError as ce:
                        findings.append({
                            "resource_type": "S3 Bucket",
                            "resource_name": bucket_name,
                            "check": "Bucket Versioning Check",
                            "status": "ERROR",
                            "detail": str(ce)
                        })

                    # 2. Check Object Lock
                    try:
                        lock_config = self.s3.get_object_lock_configuration(Bucket=bucket_name)
                        lock_status = lock_config.get('ObjectLockConfiguration', {}).get('ObjectLockEnabled')
                        if lock_status == 'Enabled':
                            findings.append({
                                "resource_type": "S3 Bucket",
                                "resource_name": bucket_name,
                                "check": "S3 Object Lock Enabled",
                                "status": "PASS",
                                "detail": "S3 Object Lock is active, guaranteeing WORM immutability."
                            })
                        else:
                            risk_count += 1
                            findings.append({
                                "resource_type": "S3 Bucket",
                                "resource_name": bucket_name,
                                "check": "S3 Object Lock Enabled",
                                "status": "FAIL",
                                "detail": "S3 Object Lock is not enabled on log bucket."
                            })
                    except ClientError as ce:
                        error_code = ce.response.get('Error', {}).get('Code')
                        if error_code in ['ObjectLockConfigurationNotFoundError', 'NoSuchObjectLockConfiguration']:
                            risk_count += 1
                            findings.append({
                                "resource_type": "S3 Bucket",
                                "resource_name": bucket_name,
                                "check": "S3 Object Lock Enabled",
                                "status": "FAIL",
                                "detail": "S3 Object Lock is missing. Logs can be modified or deleted by compromised credentials."
                            })
                        else:
                            findings.append({
                                "resource_type": "S3 Bucket",
                                "resource_name": bucket_name,
                                "check": "S3 Object Lock API Query",
                                "status": "ERROR",
                                "detail": str(ce)
                            })
        except Exception as e:
            findings.append({
                "resource_type": "S3 Service",
                "resource_name": "Immutability Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "You cannot secure what you cannot log: Ensure log storage buckets are strictly immutable using S3 Object Lock and Versioning to prevent tamper attacks during incidents.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto S3 environment with test scenarios:
    - A secure immutable log bucket with versioning and object lock.
    - An insecure mutable log bucket lacking object lock (Risk condition).
    """
    s3 = boto3.client('s3', region_name='us-east-1')

    # 1. Secure Immutable Log Bucket (Note: Object Lock requires ObjectLockEnabled during creation in real AWS/Moto)
    s3.create_bucket(
        Bucket='secure-audit-logs-bucket',
        ObjectLockEnabledForBucket=True
    )
    s3.put_bucket_versioning(
        Bucket='secure-audit-logs-bucket',
        VersioningConfiguration={'Status': 'Enabled'}
    )
    s3.put_object_lock_configuration(
        Bucket='secure-audit-logs-bucket',
        ObjectLockConfiguration={
            'ObjectLockEnabled': 'Enabled',
            'Rule': {
                'DefaultRetention': {
                    'Mode': 'Compliance',
                    'Days': 365
                }
            }
        }
    )

    # 2. Insecure Mutable Log Bucket (Missing Object Lock)
    s3.create_bucket(Bucket='mutable-legacy-logs')
    s3.put_bucket_versioning(
        Bucket='mutable-legacy-logs',
        VersioningConfiguration={'Status': 'Enabled'}
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate S3 immutability locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs S3 immutability audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="S3-Immutability-Auditor: Audits S3 log buckets for Object Lock and Versioning."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual S3 immutability testbed...")
            setup_mock_environment()

        auditor = S3ImmutabilityAuditor(profile=args.profile)
        report, risk_count = auditor.audit_immutability()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} mutable log storage vulnerability/vulnerabilities!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on mutable log risks
        else:
            print("\n[+] SUCCESS: S3 log immutability and Object Lock posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()