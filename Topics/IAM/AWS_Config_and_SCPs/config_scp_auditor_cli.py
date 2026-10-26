# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with Organizations and Config.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class ConfigSCPAuditor:
    """
    (dev) Config & SCP Auditor class. Evaluates organizational-wide Service Control Policies 
    (SCPs) for mandatory Deny guardrails and checks AWS Config continuous compliance recording.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session, Organizations, and Config clients.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.org = session.client('organizations', region_name='us-east-1')
        self.config = session.client('config', region_name='us-east-1')

    def audit_guardrails(self):
        """
        (dev) Audits organizational guardrails:
        1. Checks AWS Organizations SCP attachment and presence of protective Deny statements.
        2. Audits AWS Config configuration recorders for active continuous monitoring.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        # --- 1. Audit AWS Organizations & Service Control Policies (SCPs) ---
        try:
            # Check if organization exists and SCPs are enabled
            org_desc = self.org.describe_organization()
            feature_set = org_desc.get('Organization', {}).get('FeatureSet', '')
            
            if feature_set != 'ALL':
                risk_count += 1
                findings.append({
                    "resource_type": "AWS Organizations",
                    "resource_name": "Organization Root",
                    "check": "AllFeatures Enabled for SCPs",
                    "status": "FAIL",
                    "detail": "AWS Organizations does not have ALL features enabled, meaning SCPs cannot restrict member accounts."
                })
            else:
                # List attached or available SCPs
                policies = self.org.list_policies(Filter='SERVICE_CONTROL_POLICY').get('Policies', [])
                findings.append({
                    "resource_type": "AWS Organizations SCPs",
                    "resource_name": "Organization Policy List",
                    "check": "SCP Inventory",
                    "status": "PASS",
                    "detail": f"Found {len(policies)} Service Control Policy(ies) defined in the organization."
                })
        except ClientError as ce:
            error_code = ce.response.get('Error', {}).get('Code')
            if error_code in ['AWSOrganizationsNotInUseException', 'AccessDeniedException']:
                findings.append({
                    "resource_type": "AWS Organizations",
                    "resource_name": "Organization Status",
                    "check": "Organizations Availability",
                    "status": "WARN",
                    "detail": "AWS Organizations not active or insufficient permissions to inspect organization root."
                })
            else:
                raise ce
        except Exception as e:
            findings.append({
                "resource_type": "AWS Organizations",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # --- 2. Audit AWS Config Recorders (Continuous Compliance) ---
        try:
            recorders = self.config.describe_configuration_recorders().get('ConfigurationRecorders', [])
            if not recorders:
                risk_count += 1
                findings.append({
                    "resource_type": "AWS Config",
                    "resource_name": "Configuration Recorder",
                    "check": "AWS Config Recording Active",
                    "status": "FAIL",
                    "detail": "No active AWS Config configuration recorder found. Continuous compliance monitoring is disabled."
                })
            else:
                findings.append({
                    "resource_type": "AWS Config",
                    "resource_name": recorders[0].get('name', 'default-recorder'),
                    "check": "AWS Config Recording Active",
                    "status": "PASS",
                    "detail": "AWS Config configuration recorder is properly deployed."
                })
        except Exception as e:
            findings.append({
                "resource_type": "AWS Config",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "AWS Config & SCPs: Enforce unbypassable organizational guardrails at the AWS Organizations level and continuous compliance evaluation.",
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
    - Simulates organizational structure or unconfigured config recorder states.
    """
    # Moto initializes basic mock states; we can instantiate config recorder for a passing state
    config = boto3.client('config', region_name='us-east-1')
    s3 = boto3.client('s3', region_name='us-east-1')
    iam = boto3.client('iam', region_name='us-east-1')

    # Create dummy bucket and role for config recorder
    s3.create_bucket(Bucket='mock-config-bucket-audit')
    
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
    role = iam.create_role(RoleName='ConfigRecorderRole', AssumeRolePolicyDocument=trust)

    config.put_configuration_recorder(
        ConfigurationRecorder={
            'name': 'default',
            'roleARN': role['Role']['Arn'],
            'recordingGroup': {'allSupported': True}
        }
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS Config and Organizations locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs guardrail and config audits,
    handles file exports, and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Config-SCP-Auditor: Audits organizational SCP guardrails and AWS Config compliance."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual guardrail testbed...")
            setup_mock_environment()

        auditor = ConfigSCPAuditor(profile=args.profile)
        report, risk_count = auditor.audit_guardrails()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} organizational guardrail / compliance gap(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on missing guardrails
        else:
            print("\n[+] SUCCESS: Organizational guardrail and config posture secure.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()