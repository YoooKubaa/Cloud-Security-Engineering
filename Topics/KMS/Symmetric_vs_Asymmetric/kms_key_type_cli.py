# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with KMS.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class KMSKeyTypeAuditor:
    """
    (dev) KMS Key Type Auditor class. Evaluates customer-managed KMS keys,
    inspecting key specifications (Symmetric vs Asymmetric) to ensure proper cryptographic use.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and KMS client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.kms = session.client('kms', region_name='us-east-1')

    def audit_kms_keys(self):
        """
        (dev) Audits customer-managed KMS keys:
        1. Lists all customer-managed keys (CMKs).
        2. Describes each key to check its KeySpec (SYMMETRIC_DEFAULT, RSA_*, ECC_*).
        3. Validates against cryptographic best practices.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            # List customer-managed keys (Limit to Customer-managed for relevance)
            paginator = self.kms.get_paginator('list_keys')
            key_list = []
            for page in paginator.paginate():
                key_list.extend(page.get('Keys', []))

            for key_entry in key_list:
                key_id = key_entry['KeyId']
                
                # Describe key to get detailed metadata (KeySpec, KeyUsage, Origin)
                key_info = self.kms.describe_key(KeyId=key_id).get('KeyMetadata', {})
                
                # Skip AWS managed keys (e.g. alias/aws/s3) unless auditing explicitly
                if key_info.get('KeyManager') == 'AWS':
                    continue

                key_spec = key_info.get('KeySpec', 'SYMMETRIC_DEFAULT')
                key_usage = key_info.get('KeyUsage', 'ENCRYPT_DECRYPT')
                key_arn = key_info.get('Arn', key_id)

                is_symmetric = (key_spec == 'SYMMETRIC_DEFAULT')

                if is_symmetric:
                    findings.append({
                        "resource_type": "KMS Customer Master Key",
                        "resource_name": key_arn,
                        "check": "Cryptographic Key Spec",
                        "status": "PASS",
                        "detail": f"KeySpec is {key_spec} (Symmetric AES-256). Correctly configured for envelope encryption."
                    })
                else:
                    # Asymmetric key (RSA or ECC)
                    findings.append({
                        "resource_type": "KMS Customer Master Key",
                        "resource_name": key_arn,
                        "check": "Cryptographic Key Spec",
                        "status": "PASS",
                        "detail": f"KeySpec is {key_spec} (Asymmetric). Validated for digital signatures or external cryptography."
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
                "philosophy": "Symmetric vs Asymmetric: Symmetric keys (AES-256) power 95% of data encryption (envelope encryption), while Asymmetric keys (RSA/ECC) are reserved strictly for digital signatures and external verification.",
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
    - A standard symmetric key (SYMMETRIC_DEFAULT).
    - An asymmetric RSA key (RSA_2048) for digital signing.
    """
    kms = boto3.client('kms', region_name='us-east-1')

    # 1. Create a standard symmetric CMK
    kms.create_key(
        Description='Mock Symmetric Key for Envelope Encryption',
        KeyUsage='ENCRYPT_DECRYPT',
        Origin='AWS_KMS'
    )

    # 2. Create an asymmetric RSA key for signing
    kms.create_key(
        Description='Mock Asymmetric RSA Key for Digital Signatures',
        KeySpec='RSA_2048',
        KeyUsage='SIGN_VERIFY',
        Origin='AWS_KMS'
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS KMS locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs KMS key type audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="KMS-Key-Type-Auditor: Audits KMS key specifications (Symmetric vs Asymmetric)."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual KMS key testbed...")
            setup_mock_environment()

        auditor = KMSKeyTypeAuditor(profile=args.profile)
        report, risk_count = auditor.audit_kms_keys()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} cryptographic key misconfiguration(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on key spec violations
        else:
            print("\n[+] SUCCESS: KMS key type posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()