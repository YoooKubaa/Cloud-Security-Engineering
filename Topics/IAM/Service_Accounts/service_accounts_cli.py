# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with IAM.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class ServiceAccountsAuditor:
    """
    (dev) Service Accounts & Cross-Account Auditor class. Evaluates cross-account 
    trust relationships, checks for ExternalId (Confused Deputy protection), and audits workload service accounts.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and IAM client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.iam = session.client('iam', region_name='us-east-1')

    def audit_service_and_cross_accounts(self):
        """
        (dev) Audits service accounts and cross-account access posture:
        1. Identifies cross-account roles and checks for ExternalId condition scoping.
        2. Detects service-like IAM users utilizing risky static access keys.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        # Get current account ID for comparison
        try:
            current_account_id = boto3.client('sts', region_name='us-east-1').get_caller_identity()['Account']
        except Exception:
            current_account_id = "123456789012"  # Fallback for mock environments

        # --- 1. Audit Cross-Account Roles & ExternalId ---
        try:
            roles = self.iam.list_roles().get('Roles', [])
            for role in roles:
                role_name = role['RoleName']
                if role_name.startswith('aws-service-role'):
                    continue
                
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                for statement in trust_policy.get('Statement', []):
                    principal = statement.get('Principal', {})
                    aws_principal = principal.get('AWS', '')
                    
                    # Normalize principal to list if string
                    if isinstance(aws_principal, str):
                        aws_principals = [aws_principal]
                    elif isinstance(aws_principal, list):
                        aws_principals = aws_principal
                    else:
                        aws_principals = []

                    # Check if principal references an external account or ARN
                    is_cross_account = False
                    for p in aws_principals:
                        if p == '*' or (current_account_id not in p and 'arn:aws:iam::' in p):
                            is_cross_account = True
                            break

                    if is_cross_account:
                        # Check for ExternalId condition (Confused Deputy protection)
                        conditions = statement.get('Condition', {})
                        has_external_id = any('ExternalId' in cond_key for cond_type in conditions.values() for cond_key in cond_type.keys())

                        if not has_external_id:
                            risk_count += 1
                            findings.append({
                                "resource_type": "IAM Role (Cross-Account)",
                                "resource_name": role_name,
                                "check": "Confused Deputy Protection (ExternalId)",
                                "status": "FAIL",
                                "detail": "Cross-account trust policy allows external principals without requiring a mandatory ExternalId condition block."
                            })
                        else:
                            findings.append({
                                "resource_type": "IAM Role (Cross-Account)",
                                "resource_name": role_name,
                                "check": "Confused Deputy Protection (ExternalId)",
                                "status": "PASS",
                                "detail": "Cross-account trust policy correctly enforces ExternalId scoping."
                            })
        except Exception as e:
            findings.append({
                "resource_type": "IAM Roles",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # --- 2. Audit Service Accounts (Anti-pattern static keys) ---
        try:
            users = self.iam.list_users().get('Users', [])
            service_keywords = ['app', 'service', 'bot', 'daemon', 'worker']
            
            for user in users:
                username = user['UserName']
                if any(kw in username.lower() for kw in service_keywords):
                    keys = self.iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                    active_keys = [k for k in keys if k['Status'] == 'Active']
                    if active_keys:
                        risk_count += 1
                        findings.append({
                            "resource_type": "IAM User (Service Account)",
                            "resource_name": username,
                            "check": "Static Access Keys on Workload",
                            "status": "FAIL",
                            "detail": f"Service account user possesses {len(active_keys)} active static access key(s). Workloads must use IAM Roles."
                        })
        except Exception as e:
            findings.append({
                "resource_type": "IAM Users",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "Service Accounts & Cross-Account Access: Enforce temporary roles, eliminate static keys, and mandate ExternalId for cross-account trust.",
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
    - An insecure cross-account role missing ExternalId (Confused Deputy risk).
    - A service account user with active static access keys.
    """
    iam = boto3.client('iam', region_name='us-east-1')

    # 1. Insecure cross-account role missing ExternalId
    insecure_cross_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "sts:AssumeRole"
        }]
    })
    iam.create_role(RoleName='InsecureThirdPartyRole', AssumeRolePolicyDocument=insecure_cross_trust)

    # 2. Service account user with static keys
    iam.create_user(UserName='worker-app-service')
    iam.create_access_key(UserName='worker-app-service')


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS IAM locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs cross-account and service account audits,
    handles file exports, and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Service-Accounts-Auditor: Audits cross-account trust policies and workload credentials."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual cross-account testbed...")
            setup_mock_environment()

        auditor = ServiceAccountsAuditor(profile=args.profile)
        report, risk_count = auditor.audit_service_and_cross_accounts()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} cross-account / service account risk(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on cross-account vulnerabilities
        else:
            print("\n[+] SUCCESS: Service and cross-account posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()