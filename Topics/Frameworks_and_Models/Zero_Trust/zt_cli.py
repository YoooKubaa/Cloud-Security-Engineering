# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing command-line options and arguments.
import json      # (dev) Library for handling JSON serialization, used to structure audit output.
import sys       # (dev) Provides access to system-specific parameters and functions (used for exit codes and stderr).
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation library.
import boto3     # (dev) Official AWS SDK for Python to interact with cloud services.
from moto import mock_aws  # (dev) Decorator to mock AWS APIs locally in RAM for safe testing.

class ZTAuditorCLI:
    """
    (dev) Main Zero Trust auditor class. Connects to AWS and evaluates infrastructure 
    against core Zero Trust principles (e.g., explicit verification, least privilege).
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and EC2 service client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        # Initialize AWS session with an optional custom profile.
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        
        # Initialize EC2 client (Zero Trust heavily relies on compute and network segmentation).
        self.ec2 = session.client('ec2', region_name='eu-central-1')

    def scan_zero_trust_posture(self):
        """
        (dev) Executes Zero Trust audit logic focusing on compute security (IMDSv2) 
        and network microsegmentation (Security Groups).
        
        Returns:
        - tuple (report, failed_checks): Dictionary report and total number of security violations.
        """
        findings = []
        failed_checks = 0

        # --- 1. Compute Security Audit: IMDSv2 Enforcement (Zero Trust Metadata Protection) ---
        # (dev) Zero Trust requires disabling IMDSv1 to prevent SSRF credential theft attacks.
        instances = self.ec2.describe_instances()
        
        for reservation in instances.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_id = instance['InstanceId']
                
                # Extract metadata options configuration dictionary.
                metadata_options = instance.get('MetadataOptions', {})
                http_tokens = metadata_options.get('HttpTokens')
                
                # In Zero Trust, HttpTokens must be 'required' (enforcing IMDSv2).
                imds_v2_enforced = (http_tokens == 'required')

                if not imds_v2_enforced:
                    failed_checks += 1

                findings.append({
                    "service": "EC2",
                    "resource": instance_id,
                    "zero_trust_pillar": "Compute Security (IMDSv2)",
                    "check": "Metadata Service Version 2 Required",
                    "status": "PASS" if imds_v2_enforced else "FAIL"
                })

        # --- 2. Network Microsegmentation Audit: Overly Permissive Security Groups ---
        # (dev) Zero Trust network design forbids unsegmented broad access (0.0.0.0/0).
        sgs = self.ec2.describe_security_groups()['SecurityGroups']
        
        for sg in sgs:
            sg_id = sg['GroupId']
            overly_permissive = False
            
            for rule in sg.get('IpPermissions', []):
                # Check if any port range or protocol allows unrestricted access from the entire internet.
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        overly_permissive = True

            if overly_permissive:
                failed_checks += 1

            findings.append({
                "service": "EC2",
                "resource": sg_id,
                "zero_trust_pillar": "Network Microsegmentation",
                "check": "No Unrestricted Internet Ingress (0.0.0.0/0)",
                "status": "FAIL" if overly_permissive else "PASS"
            })

        # Compile final structured report dictionary.
        report = {
            "metadata": {
                "philosophy": "Zero Trust Model: Never Trust, Always Verify. Enforcing IMDSv2 and strict network boundaries.",
                "total_checks": len(findings),
                "failed_checks": failed_checks
            },
            "findings": findings
        }
        
        return report, failed_checks


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto environment with test infrastructure:
    one secure EC2 instance (IMDSv2) and one vulnerable instance (IMDSv1),
    along with restrictive and overly permissive security groups.
    """
    ec2 = boto3.client('ec2', region_name='eu-central-1')

    # Create a VPC for testing network boundaries.
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    vpc_id = vpc['Vpc']['VpcId']

    # 1. Secure Instance (IMDSv2 required)
    ec2.run_instances(
        ImageId='ami-12345678',
        MinCount=1,
        MaxCount=1,
        InstanceType='t2.micro',
        MetadataOptions={'HttpTokens': 'required'}  # Enforces Zero Trust metadata protection
    )

    # 2. Vulnerable Instance (IMDSv1 allowed / optional - FAIL)
    ec2.run_instances(
        ImageId='ami-12345678',
        MinCount=1,
        MaxCount=1,
        InstanceType='t2.micro',
        MetadataOptions={'HttpTokens': 'optional'}  # Vulnerable to SSRF token theft
    )

    # 3. Overly permissive Security Group (FAIL)
    sg = ec2.create_security_group(GroupName='permissive-sg', Description='Open SG', VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses command-line arguments, executes Zero Trust audits,
    handles reporting outputs, and manages pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="ZT-Auditor: Evaluates Zero Trust posture in AWS infrastructure."
    )
    
    # CLI Argument definitions:
    parser.add_argument('action', choices=['scan'], help="Action to execute (currently 'scan')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report (e.g., zt_results.json)", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'scan':
        # If mock flag is enabled, populate local mock infrastructure.
        if args.mock:
            print("[*] MOCK mode active. Generating virtual Zero Trust testbed...")
            setup_mock_environment()

        # Initialize auditor instance with specified profile.
        auditor = ZTAuditorCLI(profile=args.profile)
        report, failed_checks = auditor.scan_zero_trust_posture()

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
            print(f"\n[!] ERROR: Found {failed_checks} Zero Trust compliance violations.", file=sys.stderr)
            sys.exit(1)  # Break pipeline on failure
        else:
            print("\n[+] SUCCESS: Zero Trust infrastructure posture verified.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()