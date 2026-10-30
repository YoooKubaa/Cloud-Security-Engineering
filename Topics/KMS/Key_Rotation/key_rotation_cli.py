# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with KMS.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class KMSRotationAuditor:
    """
    (dev) KMS Key Rotation Auditor class. Evaluates customer-managed KMS keys
    to verify whether automatic annual key rotation is enabled.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and KMS client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.kms = session.client('kms', region_name='us-east-1')

    def audit_key_rotation(self):
        """
        (dev) Audits KMS key rotation posture:
        1. Enumerates all customer-managed keys (CMKs).
        2. Checks key rotation status via get_key_rotation_status().
        3. Flags keys where rotation is disabled.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            paginator = self.kms.get_paginator('list_keys')
            key_list = []
            for page in paginator.paginate():
                key_list.extend(page.get('Keys', []))

            for key_entry in key_list:
                key_id = key_entry['KeyId']
                key_info = self.kms.describe_key(KeyId=key_id).get('KeyMetadata', {})
                
                # Skip AWS managed keys (they auto-rotate and cannot be queried or changed by customers)
                if key_info.get('KeyManager') == 'AWS':
                    continue

                key_arn = key_info.get('Arn', key_id)

                try:
                    rotation_status = self.kms.get_key_rotation_status(KeyId=key_id)
                    is_enabled = rotation_status.get('KeyRotationEnabled', False)

                    if not is_enabled:
                        risk_count += 1
                        findings.append({
                            "resource_type": "KMS Customer Master Key",
                            "resource_name": key_arn,
                            "check": "Annual Key Rotation Enabled",
                            "status": "FAIL",
                            "detail": "Customer Managed Key does not have automatic annual key rotation enabled."
                        })
                    else:
                        findings.append({
                            "resource_type": "KMS Customer Master Key",
                            "resource_name": key_arn,
                            "check": "Annual Key Rotation Enabled",
                            "status": "PASS",
                            "detail": "Customer Managed Key has automatic annual key rotation enabled."
                        })
                except ClientError as ce:
                    findings.append({
                        "resource_type": "KMS Customer Master Key",
                        "resource_name": key_arn,
                        "check": "Key Rotation API Query",
                        "status": "ERROR",
                        "detail": str(ce)
                    })
        except Exception as e:
            findings.append({
                "resource_type": "KMS Service",
                "resource_name": "Key Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "KMS Key Rotation: Periodically rotate cryptographic material annually while maintaining the same Key ARN, minimizing blast radius without requiring data re-encryption.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto KMS environment with test scenarios:
    - A CMK with rotation enabled.
    - A CMK without rotation enabled (Risk condition).
    """
    kms = boto3.client('kms', region_name='us-east-1')

    # 1. Key WITH rotation enabled
    key1 = kms.create_key(
        Description='Mock CMK with Rotation Enabled',
        KeyUsage='ENCRYPT_DECRYPT',
        Origin='AWS_KMS'
    )
    kms.enable_key_rotation(KeyId=key1['KeyMetadata']['KeyId'])

    # 2. Key WITHOUT rotation enabled (Default state in AWS/Moto)
    kms.create_key(
        Description='Mock CMK without Rotation Enabled',
        KeyUsage='ENCRYPT_DECRYPT',
        Origin='AWS_KMS'
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS KMS locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs KMS rotation audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="KMS-Rotation-Auditor: Audits KMS customer-managed key rotation posture."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual KMS rotation testbed...")
            setup_mock_environment()

        auditor = KMSRotationAuditor(profile=args.profile)
        report, risk_count = auditor.audit_key_rotation()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} unrotated KMS customer key(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on unrotated keys
        else:
            print("\n[+] SUCCESS: KMS key rotation posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()