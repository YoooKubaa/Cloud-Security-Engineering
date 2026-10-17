# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for building command-line interfaces (CLI). Defines and parses runtime arguments.
import json      # (dev) Library for encoding and decoding JSON data. Used to generate the final structured output report.
import sys       # (dev) Provides access to interpreter variables/functions. Used here for exit codes (sys.exit) and stderr output.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation (replaces legacy os.path).
import boto3     # (dev) Official AWS SDK for Python. Enables authenticated API calls to AWS services.
from moto import mock_aws  # (dev) Decorator from 'moto' library to intercept boto3 API calls and mock AWS environment in RAM.

class SRMAuditorCLI:
    """
    (dev) Main auditor class. Handles AWS connections and executes security compliance checks
    for the customer's responsibility layer ("in the cloud").
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes AWS session and service clients.
        
        Parameters:
        - profile (str, optional): AWS profile name from ~/.aws/credentials. Defaults to None (uses 'default' or env vars).
        """
        # Initialize session with a specific profile (if provided). 'session' (boto3.Session) holds auth context.
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        
        # Initialize service clients for AWS API communication.
        # Instance attributes (self):
        # - self.s3: Client for Simple Storage Service (S3).
        # - self.ec2: Client for Elastic Compute Cloud (EC2) and networking (VPC/Security Groups).
        self.s3 = session.client('s3', region_name='eu-central-1')
        self.ec2 = session.client('ec2', region_name='eu-central-1')

    def scan_in_the_cloud_layer(self):
        """
        (dev) Executes audit logic. Fetches resources and verifies their configuration
        against customer-side security best practices.
        
        Returns:
        - tuple (report, failed_checks): 'report' is a dict with findings, 'failed_checks' is the count of failed checks (int).
        """
        # findings (list): Empty list storing result dicts for each audited resource.
        findings = []
        # failed_checks (int): Counter for failed security checks (vulnerabilities).
        failed_checks = 0

        # --- 1. S3 Audit (Data) ---
        # buckets (list): List of dicts representing all S3 buckets in the account.
        buckets = self.s3.list_buckets().get('Buckets', [])
        
        for b in buckets:  # (dev) Loop iterating over each bucket 'b' (dict).
            # name (str): Name of the current S3 bucket.
            name = b['Name']
            # bpa_status (bool): Flag indicating if Block Public Access is enabled and properly configured.
            bpa_status = False
            
            try:
                # conf (dict): Dictionary containing Block Public Access configuration for the bucket.
                conf = self.s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
                # Check if required block flags are set to True. all() returns True if all elements are True.
                bpa_status = all([conf.get('BlockPublicAcls'), conf.get('BlockPublicPolicy')])
            except Exception:
                # If configuration is missing (API error), consider BPA disabled (False).
                bpa_status = False

            # Increment failure counter if BPA is disabled.
            if not bpa_status: failed_checks += 1
            
            # Append finding metadata to the results list.
            findings.append({
                "service": "S3",
                "resource": name,
                "responsibility_layer": "Data Security (Customer)",
                "check": "Block Public Access Enabled",
                "status": "PASS" if bpa_status else "FAIL"
            })

        # --- 2. EC2 Audit (Network / Patching boundary) ---
        # sgs (list): List of all Security Groups in the region.
        sgs = self.ec2.describe_security_groups()['SecurityGroups']
        
        for sg in sgs:  # (dev) Loop over each Security Group 'sg'.
            # sg_id (str): Security Group ID (e.g., sg-01234abcd).
            sg_id = sg['GroupId']
            # open_ssh (bool): Flag indicating if SSH port 22 is open to 0.0.0.0/0.
            open_ssh = False
            
            # rule (dict): Loop over inbound rules (IpPermissions).
            for rule in sg.get('IpPermissions', []):
                # Check if rule target/from port is SSH (22).
                if rule.get('FromPort') == 22 or rule.get('ToPort') == 22:
                    # ip_range (dict): Loop over defined IP ranges.
                    for ip_range in rule.get('IpRanges', []):
                        # If CIDR is '0.0.0.0/0' (entire internet), mark as vulnerable.
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            open_ssh = True

            # Increment failure counter if open SSH rule is found.
            if open_ssh: failed_checks += 1

            findings.append({
                "service": "EC2",
                "resource": sg_id,
                "responsibility_layer": "Network & Firewall (Customer)",
                "check": "SSH Port 22 Not Public",
                "status": "FAIL" if open_ssh else "PASS"
            })

        # report (dict): Final data structure grouping metadata and detailed findings.
        report = {
            "metadata": {
                "philosophy": "Customer is responsible for security 'IN the cloud' (services configuration, IAM, data, patching).",
                "total_checks": len(findings),
                "failed_checks": failed_checks
            },
            "findings": findings
        }
        
        # Returns a tuple used by the CLI runner to determine output and exit code.
        return report, failed_checks


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Mock helper function. Generates vulnerable and secure infrastructure in RAM
    to enable unit testing or demonstration without real cloud deployment.
    """
    # Local client instances intercepted by moto to create resources in RAM.
    s3 = boto3.client('s3', region_name='eu-central-1')
    ec2 = boto3.client('ec2', region_name='eu-central-1')

    # Secure bucket - proper S3 API usage for hardened configuration.
    s3.create_bucket(Bucket='secure-data-bucket', CreateBucketConfiguration={'LocationConstraint': 'eu-central-1'})
    s3.put_public_access_block(Bucket='secure-data-bucket', PublicAccessBlockConfiguration={'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True})
    
    # Vulnerable bucket (FAIL) - missing BPA simulates customer misconfiguration.
    s3.create_bucket(Bucket='vulnerable-leak-bucket', CreateBucketConfiguration={'LocationConstraint': 'eu-central-1'})

    # Vulnerable Security Group (FAIL) - simulates exposed SSH network rule.
    # vpc (dict): Virtual Private Cloud context required to create a Security Group.
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    # sg (dict): Created Security Group attached to the VPC.
    sg = ec2.create_security_group(GroupName='insecure-sg', Description='SSH Open', VpcId=vpc['Vpc']['VpcId'])
    # Add ingress rule allowing port 22 from 0.0.0.0/0.
    ec2.authorize_security_group_ingress(GroupId=sg['GroupId'], IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Decorator causing boto3 API calls inside main() or child calls to be routed to Moto RAM mock.
def main():
    """
    (dev) Application entry point. Configures CLI interface, parses arguments,
    executes audit, handles output reporting and exit codes.
    """
    # parser (ArgumentParser): Object managing CLI argument configuration.
    parser = argparse.ArgumentParser(
        description="SRM-Auditor: Customer responsibility scanner ('In The Cloud')."
    )
    
    # Individual argument definitions:
    # 'action': (Positional argument) Requires action name.
    parser.add_argument('action', choices=['scan'], help="Action to execute (currently 'scan')")
    # '--profile': (Optional flag) Overrides default AWS profile.
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    # '--output': (Optional flag) Path to save the output JSON report.
    parser.add_argument('--output', type=str, help="File path to save JSON report (e.g., results.json)", default=None)
    # '--mock': (Boolean flag) Enables in-memory virtual infrastructure testing.
    parser.add_argument('--mock', action='store_true', help="Run auditor in isolated, virtual Moto environment")
    
    # args (Namespace): Parsed command-line arguments.
    args = parser.parse_args()

    if args.action == 'scan':
        # If --mock flag is set, populate RAM with mock AWS resources.
        if args.mock:
            print("[*] MOCK mode active. Generating virtual infrastructure...")
            setup_mock_environment()

        # auditor (SRMAuditorCLI): Auditor instance passing user profile.
        auditor = SRMAuditorCLI(profile=args.profile)
        # Unpack tuple results.
        report, failed_checks = auditor.scan_in_the_cloud_layer()

        # json_output (str): Formatted JSON string with 4-space indentation.
        json_output = json.dumps(report, indent=4)

        # Save logic using pathlib
        if args.output:
            # output_path (Path): Path object representing the target output file.
            output_path = Path(args.output)
            # Ensure output directory exists before writing file.
            output_path.parent.mkdir(parents=True, exist_ok=True)
            # Write JSON string directly to file with UTF-8 encoding.
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Results saved to file: {output_path.absolute()}")
        else:
            # Print to stdout for pipe support (e.g., | jq).
            print(json_output)

        # --- EXIT CODE HANDLING ---
        # (dev) Exit codes signal CI/CD pipelines to pass (0) or fail/break (1).
        if failed_checks > 0:
            # Write error message to stderr (keeps stdout clean for JSON piping).
            print(f"\n[!] ERROR: Detected {failed_checks} violations in customer responsibility layer (IN the cloud).", file=sys.stderr)
            # Non-zero exit code breaks CI/CD pipeline.
            sys.exit(1)
        else:
            print("\n[+] SUCCESS: 'IN the cloud' configuration complies with security standards.", file=sys.stderr)
            # Zero exit code signals successful scan.
            sys.exit(0)

# Ensures main() only executes when run directly (e.g., python srm_cli.py).
if __name__ == "__main__":
    main()
