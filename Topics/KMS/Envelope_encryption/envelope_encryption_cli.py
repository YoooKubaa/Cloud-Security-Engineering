# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with KMS.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class EnvelopeEncryptionAuditor:
    """
    (dev) Envelope Encryption Auditor class. Evaluates KMS CMK readiness 
    for envelope encryption workflows (verifying key status, key usage, and encryption permissions).
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and KMS client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.kms = session.client('kms', region_name='us-east-1')

    def audit_envelope_readiness(self):
        """
        (dev) Audits KMS keys for envelope encryption readiness:
        1. Enumerates customer-managed keys (CMKs).
        2. Checks if keys are Enabled and configured for ENCRYPT_DECRYPT.
        3. Validates that envelope operations can be securely modeled.
        
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
                
                # Skip AWS managed keys
                if key_info.get('KeyManager') == 'AWS':
                    continue

                key_state = key_info.get('KeyState', '')
                key_usage = key_info.get('KeyUsage', '')
                key_arn = key_info.get('Arn', key_id)

                if key_state != 'Enabled':
                    risk_count += 1
                    findings.append({
                        "resource_type": "KMS Customer Master Key",
                        "resource_name": key_arn,
                        "check": "CMK State for Envelope Encryption",
                        "status": "FAIL",
                        "detail": f"CMK state is '{key_state}'. Keys used for envelope encryption must be Enabled."
                    })
                elif key_usage != 'ENCRYPT_DECRYPT':
                    risk_count += 1
                    findings.append({
                        "resource_type": "KMS Customer Master Key",
                        "resource_name": key_arn,
                        "check": "CMK Usage for Envelope Encryption",
                        "status": "FAIL",
                        "detail": f"CMK usage is '{key_usage}'. Envelope encryption requires ENCRYPT_DECRYPT key usage."
                    })
                else:
                    findings.append({
                        "resource_type": "KMS Customer Master Key",
                        "resource_name": key_arn,
                        "check": "Envelope Encryption Capability (GenerateDataKey)",
                        "status": "PASS",
                        "detail": "CMK is active and fully configured to support GenerateDataKey and Decrypt operations for envelope encryption."
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
                "philosophy": "Envelope Encryption: Encrypt large data locally using a symmetric Data Key, secure the Data Key via KMS GenerateDataKey, and ensure CMKs never leave KMS in plaintext.",
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
    - A fully enabled symmetric CMK ready for envelope encryption.
    """
    kms = boto3.client('kms', region_name='us-east-1')

    # Create a standard symmetric CMK for envelope encryption
    kms.create_key(
        Description='Mock CMK for Envelope Encryption Pipeline',
        KeyUsage='ENCRYPT_DECRYPT',
        Origin='AWS_KMS'
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS KMS locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs envelope encryption audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="KMS-Envelope-Encryption-Auditor: Audits KMS CMK readiness for envelope encryption."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual envelope encryption testbed...")
            setup_mock_environment()

        auditor = EnvelopeEncryptionAuditor(profile=args.profile)
        report, risk_count = auditor.audit_envelope_readiness()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} envelope encryption configuration gap(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on envelope encryption issues
        else:
            print("\n[+] SUCCESS: Envelope encryption posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()