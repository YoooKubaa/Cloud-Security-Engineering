# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with EC2 / VPC.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class NetworkSegmentationAuditor:
    """
    (dev) Network Segmentation Auditor class. Evaluates VPC subnets, route tables,
    and instance placements to detect improper workload exposure in public subnets.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and EC2 client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.ec2 = session.client('ec2', region_name='us-east-1')

    def audit_segmentation(self):
        """
        (dev) Audits network segmentation and workload placement:
        1. Identifies Route Tables connected to Internet Gateways (Public Route Tables).
        2. Determines which subnets are associated with these public route tables.
        3. Scans EC2 instances running in those public subnets and flags non-edge workloads.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            # 1. Find all route tables with routes to an Internet Gateway
            route_tables = self.ec2.describe_route_tables().get('RouteTables', [])
            public_subnet_ids = set()

            for rt in route_tables:
                has_igw = False
                for route in rt.get('Routes', []):
                    dest = route.get('DestinationCidrBlock', '')
                    gw_id = route.get('GatewayId', '')
                    if dest == '0.0.0.0/0' and gw_id.startswith('igw-'):
                        has_igw = True
                        break

                if has_igw:
                    for assoc in rt.get('Associations', []):
                        subnet_id = assoc.get('SubnetId')
                        if subnet_id:
                            public_subnet_ids.add(subnet_id)

            # 2. Audit instances running in public subnets
            instances = self.ec2.describe_instances().get('Reservations', [])
            for reservation in instances:
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    subnet_id = instance.get('SubnetId')
                    state = instance.get('State', {}).get('Name')

                    if state == 'terminated':
                        continue

                    # Extract instance name tag if available
                    name_tag = instance_id
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            name_tag = f"{tag['Value']} ({instance_id})"
                            break

                    if subnet_id in public_subnet_ids:
                        # Check if it's explicitly tagged as an allowed edge workload (e.g. ALB/NAT/Bastion)
                        is_allowed_public = False
                        for tag in instance.get('Tags', []):
                            if tag['Key'].lower() in ['role', 'type', 'workload'] and any(kw in tag['Value'].lower() for kw in ['nat', 'bastion', 'alb', 'edge', 'gateway']):
                                is_allowed_public = True
                                break

                        if not is_allowed_public:
                            risk_count += 1
                            findings.append({
                                "resource_type": "EC2 Instance",
                                "resource_name": name_tag,
                                "check": "Public Subnet Workload Exposure",
                                "status": "FAIL",
                                "detail": "Application or database workload instance is running inside a public subnet (routed to an Internet Gateway). Workloads must reside in private subnets."
                            })
                        else:
                            findings.append({
                                "resource_type": "EC2 Instance",
                                "resource_name": name_tag,
                                "check": "Public Subnet Edge Placement",
                                "status": "PASS",
                                "detail": "Instance in public subnet is correctly designated as an authorized edge component (NAT/Bastion/Gateway)."
                            })
                    else:
                        findings.append({
                            "resource_type": "EC2 Instance",
                            "resource_name": name_tag,
                            "check": "Private Subnet Isolation",
                            "status": "PASS",
                            "detail": "Instance is correctly placed within a private subnet."
                        })
        except Exception as e:
            findings.append({
                "resource_type": "EC2 / VPC Service",
                "resource_name": "Segmentation Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "Network Segmentation: Enforce Zero Trust by isolating workloads into private tiers, keeping public subnets strictly for ALBs and NAT gateways to eliminate lateral movement.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto EC2/VPC environment with test scenarios:
    - A public subnet containing an insecure unlabelled app instance (Risk condition).
    """
    ec2 = boto3.client('ec2', region_name='us-east-1')

    vpcs = ec2.describe_vpcs().get('Vpcs', [])
    if vpcs:
        vpc_id = vpcs[0]['VpcId']
        
        # Create public subnet
        pub_subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.0.10.0/24')
        subnet_id = pub_subnet['Subnet']['SubnetId']

        # Launch an EC2 instance in the public subnet without edge tags (Risk)
        ec2.run_instances(
            ImageId='ami-0abcdef1234567890',
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.micro',
            SubnetId=subnet_id,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name', 'Value': 'InsecureAppServer'}]
            }]
        )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate segmentation state locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs segmentation audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Network-Segmentation-Auditor: Audits VPC subnet workload placements against Zero Trust."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual segmentation testbed...")
            setup_mock_environment()

        auditor = NetworkSegmentationAuditor(profile=args.profile)
        report, risk_count = auditor.audit_segmentation()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} network segmentation violation(s)! Workloads exposed in public subnets.", file=sys.stderr)
            sys.exit(1)  # Break pipeline on segmentation risks
        else:
            print("\n[+] SUCCESS: Network segmentation and workload placement posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()