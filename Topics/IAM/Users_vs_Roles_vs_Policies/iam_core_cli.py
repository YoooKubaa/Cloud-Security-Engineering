# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting inventory/audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with IAM.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class IAMCoreAuditor:
    """
    (dev) IAM Core Auditor class. Validates security hygiene across IAM users 
    (long-term credentials) and IAM roles (trust policies and assume-role bindings).
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and IAM client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        # IAM is a global service, but region is required for boto3 client instantiation.
        self.iam = session.client('iam', region_name='us-east-1')

    def audit_iam_posture(self):
        """
        (dev) Audits core IAM primitives:
        1. Users: Checks for active long-term access keys.
        2. Roles: Inspects Trust Policies for wildcards or over-permissive principals.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        # --- 1. Audit IAM Users (Human / Legacy Identification) ---
        try:
            users = self.iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                keys = self.iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                active_keys = [k for k in keys if k['Status'] == 'Active']
                
                has_active_keys = len(active_keys) > 0
                if has_active_keys:
                    risk_count += 1

                findings.append({
                    "resource_type": "IAM User",
                    "resource_name": username,
                    "check": "Active Long-term Access Keys",
                    "status": "FAIL" if has_active_keys else "PASS",
                    "detail": f"Found {len(active_keys)} active access key(s). Users should rely on federation/roles where possible."
                })
        except Exception as e:
            findings.append({
                "resource_type": "IAM User",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # --- 2. Audit IAM Roles (Trust Policy Evaluation) ---
        try:
            roles = self.iam.list_roles().get('Roles', [])
            for role in roles:
                role_name = role['RoleName']
                
                # Skip AWS service-linked roles to avoid noise
                if role_name.startswith('aws-service-role') or 'ServiceLinkedRole' in role.get('Path', ''):
                    continue
                
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                is_over_permissive = False
                
                # Parse trust policy statements to detect wildcard principals
                for statement in trust_policy.get('Statement', []):
                    principal = statement.get('Principal', {})
                    
                    # Check if principal allows wildcard '*' (anyone can assume)
                    if principal == '*' or principal.get('AWS') == '*':
                        is_over_permissive = True

                if is_over_permissive:
                    risk_count += 1

                findings.append({
                    "resource_type": "IAM Role",
                    "resource_name": role_name,
                    "check": "Trust Policy Principal Evaluation",
                    "status": "FAIL" if is_over_permissive else "PASS",
                    "detail": "Wildcard principal detected in Trust Policy!" if is_over_permissive else "Trust policy scoped securely."
                })
        except Exception as e:
            findings.append({
                "resource_type": "IAM Role",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # Compile structured report dictionary
        report = {
            "metadata": {
                "philosophy": "IAM Core: Enforce strict separation between human users and workload roles, validating trust boundaries.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto IAM environment with test scenarios:
    - An IAM user with an active access key (Risk condition)
    - An IAM role with a secure trust policy
    """
    iam = boto3.client('iam', region_name='us-east-1')

    # 1. Create a user with active access keys
    iam.create_user(UserName='legacy-contractor')
    iam.create_access_key(UserName='legacy-contractor')

    # 2. Create a secure role with EC2 service principal trust policy
    trust_policy_json = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    })
    iam.create_role(
        RoleName='SecureAppRole',
        AssumeRolePolicyDocument=trust_policy_json
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS IAM locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs IAM audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="IAM-Core-Auditor: Audits IAM users, access keys, and role trust policies."
    )
    
    # CLI Argument definitions:
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual IAM testbed...")
            setup_mock_environment()

        auditor = IAMCoreAuditor(profile=args.profile)
        report, risk_count = auditor.audit_iam_posture()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} IAM configuration risk(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on identity hygiene or trust policy violations
        else:
            print("\n[+] SUCCESS: IAM core posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()