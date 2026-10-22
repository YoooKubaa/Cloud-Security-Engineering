# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with IAM and EC2.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class MachineIdentityAuditor:
    """
    (dev) Machine Identity Auditor class. Evaluates workload identity hygiene:
    1. Detects service-like IAM users utilizing risky static access keys.
    2. Audits EC2 instances for IMDSv2 enforcement (SSRF protection) and Instance Profiles.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session, IAM, and EC2 clients.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.iam = session.client('iam', region_name='us-east-1')
        self.ec2 = session.client('ec2', region_name='us-east-1')

    def audit_machine_identities(self):
        """
        (dev) Audits machine identity security posture across IAM and EC2:
        - Checks for service accounts (users with app/bot/service keywords) having access keys.
        - Checks EC2 instances for IMDSv2 enforcement and Instance Profile bindings.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        # --- 1. Audit IAM Users for Anti-Pattern Service Accounts ---
        try:
            users = self.iam.list_users().get('Users', [])
            service_keywords = ['app', 'service', 'bot', 'pipeline', 'ci', 'daemon']
            
            for user in users:
                username = user['UserName']
                lower_name = username.lower()
                
                # Check if username suggests a machine/service account
                is_service_name = any(kw in lower_name for kw in service_keywords)
                if is_service_name:
                    keys = self.iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                    active_keys = [k for k in keys if k['Status'] == 'Active']
                    
                    if active_keys:
                        risk_count += 1
                        findings.append({
                            "resource_type": "IAM User (Service Account)",
                            "resource_name": username,
                            "check": "Static Access Keys on Workload Identity",
                            "status": "FAIL",
                            "detail": f"Service-like identity has {len(active_keys)} active static access key(s). Workloads must use IAM Roles."
                        })
        except Exception as e:
            findings.append({
                "resource_type": "IAM User",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # --- 2. Audit EC2 Compute Workloads (IMDSv2 & Instance Profiles) ---
        try:
            reservations = self.ec2.describe_instances().get('Reservations', [])
            for reservation in reservations:
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    
                    # Check IMDSv2 Enforcement (HttpTokens)
                    metadata_options = instance.get('MetadataOptions', {})
                    http_tokens = metadata_options.get('HttpTokens', 'optional')
                    imds_v2_required = (http_tokens == 'required')

                    if not imds_v2_required:
                        risk_count += 1
                        findings.append({
                            "resource_type": "EC2 Instance",
                            "resource_name": instance_id,
                            "check": "IMDSv2 Enforcement (SSRF Protection)",
                            "status": "FAIL",
                            "detail": "IMDSv2 is NOT strictly required. Vulnerable to SSRF-based credential theft (IMDSv1 enabled)."
                        })
                    else:
                        findings.append({
                            "resource_type": "EC2 Instance",
                            "resource_name": instance_id,
                            "check": "IMDSv2 Enforcement (SSRF Protection)",
                            "status": "PASS",
                            "detail": "IMDSv2 is strictly enforced."
                        })

                    # Check Instance Profile binding
                    has_instance_profile = 'IamInstanceProfile' in instance
                    if not has_instance_profile:
                        findings.append({
                            "resource_type": "EC2 Instance",
                            "resource_name": instance_id,
                            "check": "IAM Instance Profile Binding",
                            "status": "WARN",
                            "detail": "Instance lacks an attached IAM Instance Profile."
                        })
        except Exception as e:
            findings.append({
                "resource_type": "EC2 Instance",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "Machine Identity: Non-human workloads must use IAM roles with IMDSv2 protection, never long-term static access keys.",
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
    - An anti-pattern service IAM user with an active long-term access key.
    - An insecure EC2 instance with IMDSv1 enabled (HttpTokens = optional).
    """
    iam = boto3.client('iam', region_name='us-east-1')
    ec2 = boto3.client('ec2', region_name='us-east-1')

    # 1. Anti-pattern service user with access keys
    iam.create_user(UserName='app-service-account')
    iam.create_access_key(UserName='app-service-account')

    # 2. Insecure EC2 instance (IMDSv1 allowed by default in basic create, simulating legacy)
    ec2.run_instances(
        ImageId='ami-12345678',
        MinCount=1,
        MaxCount=1,
        InstanceType='t2.micro'
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS IAM and EC2 locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs machine identity audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Machine-Identity-Auditor: Audits workload identities, access keys, and IMDSv2 enforcement."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual machine identity testbed...")
            setup_mock_environment()

        auditor = MachineIdentityAuditor(profile=args.profile)
        report, risk_count = auditor.audit_machine_identities()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} machine identity / metadata risk(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on machine identity violations
        else:
            print("\n[+] SUCCESS: Machine identity posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()