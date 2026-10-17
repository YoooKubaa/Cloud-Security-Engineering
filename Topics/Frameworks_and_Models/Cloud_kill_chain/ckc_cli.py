# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing command-line parameters.
import json      # (dev) Library for structuring and exporting audit reports in JSON format.
import sys       # (dev) Provides system-level functions for exit codes and error logging.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation library.
import boto3     # (dev) Official AWS SDK for Python for cloud resource querying.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class CKCAuditorCLI:
    """
    (dev) Cloud Kill Chain auditor class. Evaluates AWS account configurations 
    against critical threat vectors across different Kill Chain phases 
    (Defense Evasion, Privilege Escalation, Initial Access).
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and required service clients.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        # Initialize session with an optional custom profile.
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        
        # Initialize clients for IAM (PrivEsc / Persistence) and CloudTrail (Defense Evasion).
        self.iam = session.client('iam', region_name='us-east-1')
        self.cloudtrail = session.client('cloudtrail', region_name='eu-central-1')

    def audit_kill_chain_posture(self):
        """
        (dev) Audits AWS configuration against early-stage Cloud Kill Chain enablers:
        1. Defense Evasion: Ensures CloudTrail logging is active (prevents attacker blinding).
        2. Privilege Escalation / Persistence: Checks for unmanaged / risky IAM access keys.
        
        Returns:
        - tuple (report, failed_checks): Dictionary report and count of security risks.
        """
        findings = []
        failed_checks = 0

        # --- 1. Defense Evasion Check: CloudTrail Logging Status ---
        # (dev) Attackers attempt to disable logging to hide subsequent actions.
        trail_logging_active = False
        try:
            trails = self.cloudtrail.describe_trails().get('trailList', [])
            if trails:
                trail_name = trails[0]['Name']
                status = self.cloudtrail.get_trail_status(Name=trail_name)
                trail_logging_active = status.get('IsLogging', False)
        except Exception:
            trail_logging_active = False

        if not trail_logging_active:
            failed_checks += 1

        findings.append({
            "service": "CloudTrail",
            "resource": "Account Audit Trail",
            "kill_chain_stage": "Defense Evasion",
            "check": "Audit Logging Active (Prevents Blinding)",
            "status": "PASS" if trail_logging_active else "FAIL"
        })

        # --- 2. Initial Access & Persistence Check: IAM Access Key Exposure ---
        # (dev) Long-lived access keys are primary targets for Initial Access and persistence backdoors.
        try:
            users = self.iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                keys = self.iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                
                # Flag if user has active access keys (potential risk if unrotated)
                has_active_keys = any(key['Status'] == 'Active' for key in keys)
                
                # For demonstration, we track user keys as a structural finding
                findings.append({
                    "service": "IAM",
                    "resource": f"User: {username}",
                    "kill_chain_stage": "Initial Access / Persistence",
                    "check": "Active Access Keys Count: " + str(len(keys)),
                    "status": "WARNING" if has_active_keys else "PASS"
                })
        except Exception as e:
            findings.append({
                "service": "IAM",
                "resource": "IAM User Enumeration",
                "kill_chain_stage": "Discovery",
                "check": "API Access Evaluation",
                "status": "ERROR"
            })

        # Compile final structured report dictionary
        report = {
            "metadata": {
                "philosophy": "Cloud Kill Chain: Prevent rapid compromise by detecting early-stage vectors (Discovery, PrivEsc, Defense Evasion).",
                "total_checks": len(findings),
                "failed_checks": failed_checks
            },
            "findings": findings
        }
        
        return report, failed_checks


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto environment with test assets:
    - Sets up an IAM user with access keys.
    - Simulates CloudTrail configuration state.
    """
    iam = boto3.client('iam', region_name='us-east-1')
    cloudtrail = boto3.client('cloudtrail', region_name='eu-central-1')

    # Create a test IAM user with an active access key (Initial Access / Persistence vector)
    iam.create_user(UserName='developer-service-account')
    iam.create_access_key(UserName='developer-service-account')

    # Create a CloudTrail trail (Defense Evasion defense mechanism)
    cloudtrail.create_trail(Name='security-audit-trail', S3BucketName='audit-logs-bucket')
    cloudtrail.start_logging(Name='security-audit-trail')


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses command-line arguments, executes Cloud Kill Chain audits,
    handles reporting outputs, and manages pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="CKC-Auditor: Evaluates Cloud Kill Chain posture in AWS environments."
    )
    
    # CLI Argument definitions:
    parser.add_argument('action', choices=['scan'], help="Action to execute (currently 'scan')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report (e.g., ckc_results.json)", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'scan':
        # If mock flag is enabled, populate local mock infrastructure.
        if args.mock:
            print("[*] MOCK mode active. Generating virtual Cloud Kill Chain testbed...")
            setup_mock_environment()

        # Initialize auditor instance with specified profile.
        auditor = CKCAuditorCLI(profile=args.profile)
        report, failed_checks = auditor.audit_kill_chain_posture()

        # Convert report dictionary to formatted JSON string.
        json_output = json.dumps(report, indent=4)

        # Handle file export using pathlib if output path is provided.
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Results successfully written to: {output_path.absolute()}")
        else:
            # Print JSON to stdout for piping (e.g., to jq).
            print(json_output)

        # --- PIPELINE EXIT CODE HANDLING ---
        if failed_checks > 0:
            print(f"\n[!] ERROR: Found {failed_checks} Cloud Kill Chain posture vulnerabilities (e.g., disabled audit logging).", file=sys.stderr)
            sys.exit(1)  # Break pipeline on failure
        else:
            print("\n[+] SUCCESS: Cloud Kill Chain defense posture verified.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()