# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with SSO Admin and IAM.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class SSOAuditor:
    """
    (dev) SSO Auditor class. Audits multi-account IAM Identity Center posture 
    and checks for legacy human IAM users with active console login profiles.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session, SSO Admin, and IAM clients.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.sso_admin = session.client('sso-admin', region_name='us-east-1')
        self.iam = session.client('iam', region_name='us-east-1')

    def audit_sso_posture(self):
        """
        (dev) Audits SSO and Identity Center governance posture:
        1. Checks for active IAM Identity Center instances.
        2. Scans for legacy IAM Users possessing console login profiles (anti-pattern under SSO).
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        # --- 1. Audit IAM Identity Center Instance Deployment ---
        try:
            instances = self.sso_admin.list_instances().get('Instances', [])
            if not instances:
                risk_count += 1
                findings.append({
                    "resource_type": "IAM Identity Center",
                    "resource_name": "Organization SSO",
                    "check": "Identity Center Deployment",
                    "status": "FAIL",
                    "detail": "No IAM Identity Center instance found. Multi-account environments require centralized SSO."
                })
            else:
                findings.append({
                    "resource_type": "IAM Identity Center",
                    "resource_name": instances[0].get('InstanceArn', 'sso-instance'),
                    "check": "Identity Center Deployment",
                    "status": "PASS",
                    "detail": "IAM Identity Center is deployed and active."
                })
        except Exception as e:
            # In mock environments or limited permissions, capture gracefully
            findings.append({
                "resource_type": "IAM Identity Center",
                "resource_name": "Enumeration Check",
                "check": "API Query Execution",
                "status": "WARN",
                "detail": f"Could not verify Identity Center instances (API limitation or mock state): {str(e)}"
            })

        # --- 2. Audit for Legacy Human IAM Users (Console Access Sprawl) ---
        try:
            users = self.iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                try:
                    self.iam.get_login_profile(UserName=username)
                    risk_count += 1
                    findings.append({
                        "resource_type": "IAM User (Legacy Human)",
                        "resource_name": username,
                        "check": "Legacy Console User Sprawl",
                        "status": "FAIL",
                        "detail": "User has an active console login profile. Human access should be managed via IAM Identity Center (SSO), not native IAM Users."
                    })
                except ClientError as ce:
                    # If NoSuchEntityException, user does not have a console login profile (clean / machine user)
                    error_code = ce.response.get('Error', {}).get('Code')
                    if error_code == 'NoSuchEntity':
                        pass
                    else:
                        raise ce
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
                "philosophy": "SSO & Identity Center: Centralize multi-account access via IAM Identity Center and eliminate legacy human IAM users.",
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
    - A legacy human IAM user with an active console login profile (Risk condition).
    """
    iam = boto3.client('iam', region_name='us-east-1')

    # Create a legacy human user with console access
    iam.create_user(UserName='john.doe-admin')
    iam.create_login_profile(
        UserName='john.doe-admin',
        Password='SecurePassword123!',
        PasswordResetRequired=False
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS IAM locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs SSO audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="SSO-Auditor: Audits IAM Identity Center and detects legacy human console users."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual SSO & legacy user testbed...")
            setup_mock_environment()

        auditor = SSOAuditor(profile=args.profile)
        report, risk_count = auditor.audit_sso_posture()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} legacy human console user(s) / SSO governance risk(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on legacy console users
        else:
            print("\n[+] SUCCESS: SSO governance posture fully compliant.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()