# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing command-line parameters.
import json      # (dev) Library for structuring and exporting inventory/audit reports in JSON format.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation library.
import boto3     # (dev) Official AWS SDK for Python to query cloud infrastructure.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class ASMAuditorCLI:
    """
    (dev) AWS Attack Surface Management (ASM) auditor class. Discovers and evaluates 
    external exposure vectors across network boundaries (Security Groups), 
    data storage (S3), and identity entry points (IAM).
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and required service clients.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        # Initialize session with an optional custom profile.
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        
        # Initialize clients for EC2 (Network surface), S3 (Data surface), and IAM (Identity surface).
        self.ec2 = session.client('ec2', region_name='eu-central-1')
        self.s3 = session.client('s3', region_name='eu-central-1')
        self.iam = session.client('iam', region_name='us-east-1')

    def discover_attack_surface(self):
        """
        (dev) Discovers and audits the dynamic cloud attack surface across 3 dimensions:
        1. Network Ingress Exposure (Security Groups allowing 0.0.0.0/0)
        2. Data Exposure (S3 buckets without Block Public Access)
        3. Identity Entrypoints (Active IAM access keys)
        
        Returns:
        - tuple (report, exposure_count): Dictionary report and total number of exposure findings.
        """
        findings = []
        exposure_count = 0

        # --- 1. Network Attack Surface: Public Security Groups ---
        # (dev) Identifies overly permissive firewall rules exposed to the entire internet.
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                sg_id = sg['GroupId']
                is_public = False
                
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            is_public = True

                if is_public:
                    exposure_count += 1

                findings.append({
                    "service": "EC2",
                    "resource": sg_id,
                    "surface_category": "Network Ingress",
                    "check": "Unrestricted Internet Access (0.0.0.0/0)",
                    "status": "FAIL" if is_public else "PASS"
                })
        except Exception as e:
            findings.append({
                "service": "EC2",
                "resource": "Security Groups Enumeration",
                "surface_category": "Network Ingress",
                "check": "API Query Execution",
                "status": "ERROR"
            })

        # --- 2. Data Attack Surface: S3 Public Exposure Risk ---
        # (dev) Identifies S3 buckets lacking strict public access blocks.
        try:
            buckets = self.s3.list_buckets().get('Buckets', [])
            for b in buckets:
                bucket_name = b['Name']
                bpa_active = False
                
                try:
                    conf = self.s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                    bpa_active = all([
                        conf.get('BlockPublicAcls'),
                        conf.get('BlockPublicPolicy'),
                        conf.get('IgnorePublicAcls'),
                        conf.get('RestrictPublicBuckets')
                    ])
                except Exception:
                    bpa_active = False

                if not bpa_active:
                    exposure_count += 1

                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "surface_category": "Data Storage",
                    "check": "Block Public Access Fully Enabled",
                    "status": "PASS" if bpa_active else "FAIL"
                })
        except Exception as e:
            findings.append({
                "service": "S3",
                "resource": "S3 Buckets Enumeration",
                "surface_category": "Data Storage",
                "check": "API Query Execution",
                "status": "ERROR"
            })

        # --- 3. Identity Attack Surface: Active IAM Access Keys ---
        # (dev) Inventories active credentials serving as potential entry points.
        try:
            users = self.iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                keys = self.iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                active_keys = [k for k in keys if k['Status'] == 'Active']
                
                if len(active_keys) > 0:
                    exposure_count += 1

                findings.append({
                    "service": "IAM",
                    "resource": f"User: {username}",
                    "surface_category": "Identity Access",
                    "check": f"Active Access Keys Count: {len(active_keys)}",
                    "status": "WARNING" if len(active_keys) > 0 else "PASS"
                })
        except Exception as e:
            findings.append({
                "service": "IAM",
                "resource": "IAM Users Enumeration",
                "surface_category": "Identity Access",
                "check": "API Query Execution",
                "status": "ERROR"
            })

        # Compile final structured report dictionary
        report = {
            "metadata": {
                "philosophy": "Attack Surface Management: Continuously map and evaluate dynamic cloud exposure points.",
                "total_checks": len(findings),
                "failed_checks": exposure_count
            },
            "findings": findings
        }
        
        return report, exposure_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto environment with a mix of secure and exposed assets:
    - An overly permissive Security Group (Network exposure)
    - A vulnerable S3 bucket without Public Access Block (Data exposure)
    - An IAM user with active access keys (Identity surface)
    """
    ec2 = boto3.client('ec2', region_name='eu-central-1')
    s3 = boto3.client('s3', region_name='eu-central-1')
    iam = boto3.client('iam', region_name='us-east-1')

    # 1. Network Exposure: Public Security Group
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    sg = ec2.create_security_group(GroupName='exposed-web-sg', Description='Public HTTP/SSH', VpcId=vpc['Vpc']['VpcId'])
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    )

    # 2. Data Exposure: Unprotected S3 Bucket
    s3.create_bucket(Bucket='exposed-data-bucket', CreateBucketConfiguration={'LocationConstraint': 'eu-central-1'})

    # 3. Identity Surface: IAM User with Active Keys
    iam.create_user(UserName='external-contractor')
    iam.create_access_key(UserName='external-contractor')


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses command-line arguments, executes Attack Surface discovery,
    handles reporting outputs, and manages pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="ASM-Auditor: Maps and evaluates dynamic cloud attack surface in AWS."
    )
    
    # CLI Argument definitions:
    parser.add_argument('action', choices=['scan'], help="Action to execute (currently 'scan')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report (e.g., asm_results.json)", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'scan':
        # If mock flag is enabled, populate local mock infrastructure.
        if args.mock:
            print("[*] MOCK mode active. Generating virtual Attack Surface testbed...")
            setup_mock_environment()

        # Initialize auditor instance with specified profile.
        auditor = ASMAuditorCLI(profile=args.profile)
        report, exposure_count = auditor.discover_attack_surface()

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
        if exposure_count > 0:
            print(f"\n[!] WARNING/ERROR: Detected {exposure_count} attack surface exposures (public endpoints/assets).", file=sys.stderr)
            sys.exit(1)  # Break pipeline if unwanted exposure is found
        else:
            print("\n[+] SUCCESS: Attack surface posture is fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()