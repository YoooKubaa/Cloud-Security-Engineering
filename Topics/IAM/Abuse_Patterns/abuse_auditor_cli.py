# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with IAM.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class AbuseAuditor:
    """
    (dev) Abuse Auditor class. Detects dangerous IAM abuse patterns, admin sprawl, 
    long-lived access keys, and privilege escalation paths (e.g., policy version manipulation).
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and IAM client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.iam = session.client('iam', region_name='us-east-1')

    def scan_abuse_patterns(self):
        """
        (dev) Scans AWS IAM for abuse patterns and privilege escalation vectors:
        1. Admin Sprawl: Identities attached directly to AdministratorAccess.
        2. Long-lived Keys: User access keys active in the environment.
        3. PrivEsc Vectors: Dangerous actions allowing self-escalation (e.g., CreatePolicyVersion, PutUserPolicy).
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        # --- 1. Audit Admin Sprawl & PrivEsc on Users ---
        try:
            users = self.iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                
                # Check user access keys (Long-lived credentials risk)
                keys = self.iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                active_keys = [k for k in keys if k['Status'] == 'Active']
                if active_keys:
                    findings.append({
                        "resource_type": "IAM User",
                        "resource_name": username,
                        "check": "Long-lived Access Keys",
                        "status": "WARN",
                        "detail": f"User has {len(active_keys)} active access key(s)."
                    })

                # Check attached managed policies for AdministratorAccess
                attached_policies = self.iam.list_attached_user_policies(UserName=username).get('AttachedPolicies', [])
                for pol in attached_policies:
                    if pol['PolicyName'] == 'AdministratorAccess':
                        risk_count += 1
                        findings.append({
                            "resource_type": "IAM User",
                            "resource_name": username,
                            "check": "Admin Sprawl (AdministratorAccess)",
                            "status": "FAIL",
                            "detail": "User is attached directly to AdministratorAccess managed policy."
                        })

                # Check inline policies for PrivEsc primitives
                inline_pols = self.iam.list_user_policies(UserName=username).get('PolicyNames', [])
                for pol_name in inline_pols:
                    pol_doc = self.iam.get_user_policy(UserName=username, PolicyName=pol_name).get('PolicyDocument', {})
                    for statement in pol_doc.get('Statement', []):
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Detect dangerous privilege escalation actions
                        dangerous_actions = ['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion', 'iam:PutUserPolicy', 'iam:AttachUserPolicy']
                        if any(action in actions or action == '*' for action in dangerous_actions):
                            risk_count += 1
                            findings.append({
                                "resource_type": "IAM User",
                                "resource_name": username,
                                "check": "Privilege Escalation Vector",
                                "status": "FAIL",
                                "detail": f"Inline policy contains high-risk PrivEsc action(s): {actions}"
                            })

        except Exception as e:
            findings.append({
                "resource_type": "IAM User",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # --- 2. Audit Admin Sprawl on Roles ---
        try:
            roles = self.iam.list_roles().get('Roles', [])
            for role in roles:
                role_name = role['RoleName']
                if role_name.startswith('aws-service-role'):
                    continue
                
                attached_policies = self.iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
                for pol in attached_policies:
                    if pol['PolicyName'] == 'AdministratorAccess':
                        findings.append({
                            "resource_type": "IAM Role",
                            "resource_name": role_name,
                            "check": "Admin Sprawl (AdministratorAccess)",
                            "status": "WARN",
                            "detail": "Workload role holds AdministratorAccess."
                        })
        except Exception as e:
            findings.append({
                "resource_type": "IAM Role",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "Abuse Patterns: Proactively hunt for privilege escalation paths, admin sprawl, and dangerous permission combinations.",
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
    - A user with dangerous inline policy allowing iam:CreatePolicyVersion (PrivEsc Vector)
    - A user with direct AdministratorAccess (Admin Sprawl)
    """
    iam = boto3.client('iam', region_name='us-east-1')

    # 1. PrivEsc user with dangerous inline policy
    iam.create_user(UserName='developer-sandbox')
    privesc_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
            "Resource": "*"
        }]
    })
    iam.put_user_policy(
        UserName='developer-sandbox',
        PolicyName='SelfEscalationPolicy',
        PolicyStatement=privesc_policy
    )

    # 2. Admin sprawl user
    iam.create_user(UserName='contractor-admin')
    iam.attach_user_policy(
        UserName='contractor-admin',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS IAM locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs abuse pattern audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Abuse-Auditor: Detects IAM abuse patterns and privilege escalation paths."
    )
    
    parser.add_argument('action', choices=['scan'], help="Action to execute (currently 'scan')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'scan':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual IAM abuse testbed...")
            setup_mock_environment()

        auditor = AbuseAuditor(profile=args.profile)
        report, risk_count = auditor.scan_abuse_patterns()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} privilege escalation / abuse risk(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on privilege escalation paths
        else:
            print("\n[+] SUCCESS: No high-risk IAM abuse patterns detected.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()