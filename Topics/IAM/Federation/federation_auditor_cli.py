# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with IAM.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class FederationAuditor:
    """
    (dev) Federation Auditor class. Audits IAM OpenID Connect (OIDC) providers 
    and role trust policies to ensure secure AssumeRoleWithWebIdentity configurations with strict Condition scopes.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and IAM client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.iam = session.client('iam', region_name='us-east-1')

    def audit_federation_posture(self):
        """
        (dev) Audits federation posture:
        1. Inventories OIDC identity providers.
        2. Inspects IAM roles utilizing AssumeRoleWithWebIdentity for missing Condition blocks.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        # --- 1. Audit Registered OIDC Providers ---
        try:
            oidc_providers = self.iam.list_open_id_connect_providers().get('OpenIdConnectProviderList', [])
            findings.append({
                "resource_type": "IAM OIDC Providers",
                "resource_name": "Account OIDC List",
                "check": "Provider Enumeration",
                "status": "PASS",
                "detail": f"Found {len(oidc_providers)} registered OIDC provider(s)."
            })
        except Exception as e:
            findings.append({
                "resource_type": "IAM OIDC Providers",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # --- 2. Audit Role Trust Policies for Web Identity (OIDC) ---
        try:
            roles = self.iam.list_roles().get('Roles', [])
            for role in roles:
                role_name = role['RoleName']
                if role_name.startswith('aws-service-role'):
                    continue
                
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                for statement in trust_policy.get('Statement', []):
                    action = statement.get('Action', '')
                    # Check if statement allows web identity assumption (OIDC)
                    is_web_identity = (action == 'sts:AssumeRoleWithWebIdentity' or 
                                       (isinstance(action, list) and 'sts:AssumeRoleWithWebIdentity' in action))
                    
                    if is_web_identity:
                        has_condition = 'Condition' in statement
                        
                        if not has_condition:
                            risk_count += 1
                            findings.append({
                                "resource_type": "IAM Role (OIDC Trust)",
                                "resource_name": role_name,
                                "check": "OIDC Trust Policy Condition Scope",
                                "status": "FAIL",
                                "detail": "OIDC trust policy allows AssumeRoleWithWebIdentity without a strict Condition block (missing repository/branch restriction)."
                            })
                        else:
                            findings.append({
                                "resource_type": "IAM Role (OIDC Trust)",
                                "resource_name": role_name,
                                "check": "OIDC Trust Policy Condition Scope",
                                "status": "PASS",
                                "detail": "OIDC trust policy includes condition scoping."
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
                "philosophy": "Federation & SSO: Centralize identity management via IdPs and enforce strict Condition scopes on OIDC/SAML trust policies.",
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
    - A secure OIDC role with a strict Condition block on GitHub Actions `sub`.
    - An insecure OIDC role missing the Condition block (Risk condition).
    """
    iam = boto3.client('iam', region_name='us-east-1')

    # Create mock OIDC provider for GitHub Actions
    iam.create_open_id_connect_provider(
        Url='https://token.actions.githubusercontent.com',
        ClientIDList=['sts.amazonaws.com'],
        ThumbprintList=['6556c0850239634f19b8893d924765d77c449c28']
    )

    # 1. Secure OIDC role with Condition
    secure_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": "repo:YoooKubaa/Cloud-Security-Engineering:ref:refs/heads/main"
                }
            }
        }]
    })
    iam.create_role(RoleName='SecurePipelineRole', AssumeRolePolicyDocument=secure_trust)

    # 2. Insecure OIDC role missing Condition (Risk)
    insecure_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
            "Action": "sts:AssumeRoleWithWebIdentity"
        }]
    })
    iam.create_role(RoleName='InsecurePipelineRole', AssumeRolePolicyDocument=insecure_trust)


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS IAM locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs federation audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Federation-Auditor: Audits IAM OIDC/SAML providers and trust policy condition scopes."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual federation testbed...")
            setup_mock_environment()

        auditor = FederationAuditor(profile=args.profile)
        report, risk_count = auditor.audit_federation_posture()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} insecure federation trust relationship(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on unconstrained OIDC trust policies
        else:
            print("\n[+] SUCCESS: Federation trust posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()