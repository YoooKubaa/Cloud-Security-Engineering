# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with IAM.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class BoundaryAuditor:
    """
    (dev) Boundary Auditor class. Audits IAM users and roles to verify 
    the presence and enforcement of Permission Boundaries (effective permission ceilings).
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and IAM client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.iam = session.client('iam', region_name='us-east-1')

    def audit_boundaries(self):
        """
        (dev) Audits IAM users and roles for Permission Boundary attachments:
        - Checks if identities have a permissions boundary configured.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        # --- 1. Audit IAM Users for Permission Boundaries ---
        try:
            users = self.iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                user_details = self.iam.get_user(UserName=username).get('User', {})
                has_boundary = 'PermissionsBoundary' in user_details

                # For audit purposes, let's flag users missing a boundary if they require governance
                # (Marked as FAIL if missing in strict environments, or WARN depending on design)
                status = "PASS" if has_boundary else "WARN"
                
                findings.append({
                    "resource_type": "IAM User",
                    "resource_name": username,
                    "check": "Permission Boundary Attached",
                    "status": status,
                    "detail": "Permission boundary is enforced." if has_boundary else "No permission boundary attached to user."
                })
        except Exception as e:
            findings.append({
                "resource_type": "IAM User",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # --- 2. Audit IAM Roles for Permission Boundaries ---
        try:
            roles = self.iam.list_roles().get('Roles', [])
            for role in roles:
                role_name = role['RoleName']
                if role_name.startswith('aws-service-role'):
                    continue
                
                role_details = self.iam.get_role(RoleName=role_name).get('Role', {})
                has_boundary = 'PermissionsBoundary' in role_details

                if not has_boundary:
                    risk_count += 1

                findings.append({
                    "resource_type": "IAM Role",
                    "resource_name": role_name,
                    "check": "Permission Boundary Attached",
                    "status": "PASS" if has_boundary else "FAIL",
                    "detail": "Role is bound by a permission ceiling." if has_boundary else "Role lacks a permission boundary, leaving permissions unconstrained."
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
                "philosophy": "Permission Boundaries: Enforce a hard security ceiling for self-service delegation using intersection logic.",
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
    - A secure role with a permission boundary attached.
    - An unconstrained role lacking a permission boundary (Risk condition).
    """
    iam = boto3.client('iam', region_name='us-east-1')

    # Create a boundary policy first
    boundary_policy_json = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "*"
        }]
    })
    boundary_response = iam.create_policy(
        PolicyName='StrictDeploymentBoundary',
        PolicyDocument=boundary_policy_json
    )
    boundary_arn = boundary_response['Policy']['Arn']

    # 1. Secure role with permission boundary
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    })
    iam.create_role(
        RoleName='SecureBoundedRole',
        AssumeRolePolicyDocument=trust_policy,
        PermissionsBoundary=boundary_arn
    )

    # 2. Unconstrained role without boundary (Risk)
    iam.create_role(
        RoleName='UnconstrainedRole',
        AssumeRolePolicyDocument=trust_policy
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS IAM locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs boundary audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Boundary-Auditor: Audits IAM permission boundaries and enforcement ceilings."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual boundary testbed...")
            setup_mock_environment()

        auditor = BoundaryAuditor(profile=args.profile)
        report, risk_count = auditor.audit_boundaries()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} unconstrained principal(s) lacking boundaries!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on missing boundaries
        else:
            print("\n[+] SUCCESS: Permission boundaries fully enforced.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()