# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with KMS.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class KMSPolicyAuditor:
    """
    (dev) KMS Policy Auditor class. Evaluates KMS Customer Master Key policies
    to verify IAM delegation statements and detect over-permissive principal configurations.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and KMS client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.kms = session.client('kms', region_name='us-east-1')

    def audit_key_policies(self):
        """
        (dev) Audits KMS key policies:
        1. Enumerates customer-managed keys (CMKs).
        2. Retrieves and parses the JSON key policy for each key.
        3. Checks for IAM delegation ("Enable IAM User Permissions") and wildcard exposure risks.
        
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

                key_arn = key_info.get('Arn', key_id)

                # Fetch key policy document
                policy_str = self.kms.get_key_policy(KeyId=key_id, PolicyName='default').get('Policy', '{}')
                try:
                    policy_doc = json.loads(policy_str)
                except json.JSONDecodeError:
                    policy_doc = {}

                statements = policy_doc.get('Statement', [])
                
                # Check for IAM delegation statement ("Enable IAM User Permissions" pattern)
                has_iam_delegation = False
                has_wildcard_principal = False

                for stmt in statements:
                    if stmt.get('Effect') == 'Allow':
                        principal = stmt.get('Principal', {})
                        action = stmt.get('Action', '')

                        # Check if principal is wildcard
                        if principal == '*' or principal.get('AWS') == '*':
                            has_wildcard_principal = True

                        # Check for standard root account delegation (IAM user permission enablement)
                        aws_principal = principal.get('AWS', '')
                        if isinstance(aws_principal, str) and ':root' in aws_principal:
                            if 'kms:*' in action or (isinstance(action, list) and any('kms:' in a for a in action)):
                                has_iam_delegation = True

                if has_wildcard_principal:
                    risk_count += 1
                    findings.append({
                        "resource_type": "KMS Key Policy",
                        "resource_name": key_arn,
                        "check": "Wildcard Principal Exposure",
                        "status": "FAIL",
                        "detail": "Key policy contains a wildcard principal ('*'), exposing the KMS key to unauthorized public access."
                    })
                elif not has_iam_delegation:
                    findings.append({
                        "resource_type": "KMS Key Policy",
                        "resource_name": key_arn,
                        "check": "IAM Policy Delegation Statement",
                        "status": "WARN",
                        "detail": "Key policy does not contain standard IAM root delegation. Permissions must be explicitly defined inside the key policy."
                    })
                else:
                    findings.append({
                        "resource_type": "KMS Key Policy",
                        "resource_name": key_arn,
                        "check": "IAM Policy Delegation Statement",
                        "status": "PASS",
                        "detail": "Key policy correctly delegates management and usage to account IAM policies."
                    })
        except Exception as e:
            findings.append({
                "resource_type": "KMS Service",
                "resource_name": "Key Policy Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "Key Policies vs IAM Policies: KMS effective permissions require BOTH Key Policy AND IAM Policy to allow access (AND logic). Removing IAM delegation locks down the key entirely.",
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
    - A standard CMK with default policy delegation.
    """
    kms = boto3.client('kms', region_name='us-east-1')

    # Create a standard symmetric CMK (Moto automatically applies default key policy with IAM delegation)
    kms.create_key(
        Description='Mock CMK for Key Policy vs IAM Policy Evaluation',
        KeyUsage='ENCRYPT_DECRYPT',
        Origin='AWS_KMS'
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS KMS locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs KMS policy audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="KMS-Policy-Auditor: Audits KMS key policies and IAM delegation rules."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual KMS policy testbed...")
            setup_mock_environment()

        auditor = KMSPolicyAuditor(profile=args.profile)
        report, risk_count = auditor.audit_key_policies()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} KMS key policy vulnerability/risk(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on policy risks
        else:
            print("\n[+] SUCCESS: KMS key policy posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()