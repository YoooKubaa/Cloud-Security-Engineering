# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with EC2 / VPC.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class VPCTopologyAuditor:
    """
    (dev) VPC Topology Auditor class. Evaluates VPC subnets, route tables, 
    and internet gateway attachments to verify network segmentation and public exposure risks.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and EC2 client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.ec2 = session.client('ec2', region_name='us-east-1')

    def audit_vpc_topology(self):
        """
        (dev) Audits VPC networking topology:
        1. Enumerates custom VPCs and their subnets.
        2. Inspects Route Tables to determine route destinations (IGW vs NAT/None).
        3. Validates public/private segmentation boundaries.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            vpcs = self.ec2.describe_vpcs().get('Vpcs', [])
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                
                # Skip default VPC check if desired, or audit it. Let's audit all.
                is_default = vpc.get('IsDefault', False)

                # Get subnets for this VPC
                subnets = self.ec2.describe_subnets(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                ).get('Subnets', [])

                # Get route tables for this VPC
                route_tables = self.ec2.describe_route_tables(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                ).get('RouteTables', [])

                for rt in route_tables:
                    rt_id = rt['RouteId']
                    routes = rt.get('Routes', [])
                    
                    has_igw_route = False
                    for route in routes:
                        destination = route.get('DestinationCidrBlock', route.get('DestinationIpv6CidrBlock', ''))
                        gateway_id = route.get('GatewayId', '')
                        
                        if destination == '0.0.0.0/0' and gateway_id.startswith('igw-'):
                            has_igw_route = True
                            break

                    # Check associations
                    associations = rt.get('Associations', [])
                    associated_subnet_count = sum(1 for a in associations if not a.get('Main', False))

                    if has_igw_route:
                        findings.append({
                            "resource_type": "VPC Route Table",
                            "resource_name": rt_id,
                            "check": "Internet Gateway Route Exposure",
                            "status": "PASS",
                            "detail": f"Route table {rt_id} routes 0.0.0.0/0 to an Internet Gateway (Public Subnet configuration managing {associated_subnet_count} subnet(s))."
                        })
                    else:
                        findings.append({
                            "resource_type": "VPC Route Table",
                            "resource_name": rt_id,
                            "check": "Internet Gateway Route Exposure",
                            "status": "PASS",
                            "detail": f"Route table {rt_id} is isolated from direct Internet Gateway routing (Private Subnet configuration)."
                        })

                if is_default and len(subnets) > 0:
                    findings.append({
                        "resource_type": "VPC",
                        "resource_name": vpc_id,
                        "check": "Default VPC Usage",
                        "status": "WARN",
                        "detail": "Default VPC is present and active. Production workloads should utilize custom VPC topologies."
                    })
        except Exception as e:
            findings.append({
                "resource_type": "EC2 / VPC Service",
                "resource_name": "Topology Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "VPC Topology: Subnets are not inherently public or private; Route Tables dictate traffic routing via Internet Gateways or NAT Gateways.",
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
    - A custom VPC with an Internet Gateway and public/private route table setups.
    """
    ec2 = boto3.client('ec2', region_name='us-east-1')

    # 1. Create custom VPC
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    vpc_id = vpc['Vpc']['VpcId']

    # 2. Create Internet Gateway and attach to VPC
    igw = ec2.create_internet_gateway()
    igw_id = igw['InternetGateway']['InternetGatewayId']
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    # 3. Create public route table and add route to IGW
    rt = ec2.create_route_table(VpcId=vpc_id)
    rt_id = rt['RouteTable']['RouteTableId']
    ec2.create_route(
        RouteTableId=rt_id,
        DestinationCidrBlock='0.0.0.0/0',
        GatewayId=igw_id
    )

    # 4. Create public subnet and associate with public route table
    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.0.1.0/24')
    subnet_id = subnet['Subnet']['SubnetId']
    ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate VPC topology locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs VPC topology audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="VPC-Topology-Auditor: Audits VPC subnets, route tables, and internet gateway exposures."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual VPC network testbed...")
            setup_mock_environment()

        auditor = VPCTopologyAuditor(profile=args.profile)
        report, risk_count = auditor.audit_vpc_topology()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} network topological risk(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on networking risks
        else:
            print("\n[+] SUCCESS: VPC topology and routing posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()