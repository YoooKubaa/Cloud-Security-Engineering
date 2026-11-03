# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with EC2 VPC Endpoints.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class PrivateLinkAuditor:
    """
    (dev) PrivateLink & VPC Endpoints Auditor class. Evaluates VPC endpoints,
    inspects endpoint types (Gateway vs Interface), and audits endpoint access policies.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and EC2 client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.ec2 = session.client('ec2', region_name='us-east-1')

    def audit_vpc_endpoints(self):
        """
        (dev) Audits VPC endpoints and private link configurations:
        1. Enumerates all VPC endpoints in the account.
        2. Evaluates endpoint type (Gateway vs Interface).
        3. Inspects attached policy documents for wildcard principal exposures.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            endpoints = self.ec2.describe_vpc_endpoints().get('VpcEndpoints', [])
            
            if not endpoints:
                risk_count += 1
                findings.append({
                    "resource_type": "VPC Endpoints",
                    "resource_name": "Account VPC Endpoints",
                    "check": "Private Endpoint Deployment",
                    "status": "FAIL",
                    "detail": "No VPC Endpoints found in the account. Workloads relying on AWS APIs may be traversing public internet / NAT Gateways."
                })
            else:
                for vpce in endpoints:
                    vpce_id = vpce['VpcEndpointId']
                    service_name = vpce['ServiceName']
                    vpce_type = vpce['VpcEndpointType']
                    state = vpce['State']
                    policy_str = vpce.get('PolicyDocument', '{}')

                    try:
                        policy_doc = json.loads(policy_str) if policy_str else {}
                    except json.JSONDecodeError:
                        policy_doc = {}

                    # Check policy for open wildcard principal
                    has_wildcard_principal = False
                    statements = policy_doc.get('Statement', [])
                    for stmt in statements:
                        if stmt.get('Effect') == 'Allow':
                            principal = stmt.get('Principal', {})
                            if principal == '*' or principal.get('AWS') == '*':
                                has_wildcard_principal = True
                                break

                    if state != 'available':
                        risk_count += 1
                        findings.append({
                            "resource_type": "VPC Endpoint",
                            "resource_name": vpce_id,
                            "check": "Endpoint Operational State",
                            "status": "FAIL",
                            "detail": f"VPC Endpoint state is '{state}' (not available)."
                        })
                    elif has_wildcard_principal:
                        risk_count += 1
                        findings.append({
                            "resource_type": "VPC Endpoint",
                            "resource_name": f"{vpce_id} ({service_name})",
                            "check": "Endpoint Policy Principal",
                            "status": "FAIL",
                            "detail": f"VPC Endpoint policy allows unrestricted wildcard principal ('*'). Access should be scoped to account or IAM roles."
                        })
                    else:
                        findings.append({
                            "resource_type": "VPC Endpoint",
                            "resource_name": f"{vpce_id} ({service_name})",
                            "check": f"{vpce_type} Endpoint Configuration",
                            "status": "PASS",
                            "detail": f"VPC Endpoint ({vpce_type}) for {service_name} is active and properly scoped."
                        })
        except Exception as e:
            findings.append({
                "resource_type": "EC2 / VPC Service",
                "resource_name": "Endpoint Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "PrivateLink & Endpoints: Route internal AWS API traffic securely via private endpoints (Gateway vs Interface), eliminating NAT Gateway exposure and public internet transit.",
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
    - Creates a custom VPC and a Gateway VPC Endpoint for S3.
    """
    ec2 = boto3.client('ec2', region_name='us-east-1')

    # Get default VPC id
    vpcs = ec2.describe_vpcs().get('Vpcs', [])
    if vpcs:
        vpc_id = vpcs[0]['VpcId']
        rt_tables = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        rt_id = rt_tables['RouteTables'][0]['RouteTableId']

        # Create Gateway VPC Endpoint for S3
        ec2.create_vpc_endpoint(
            VpcId=vpc_id,
            ServiceName='com.amazonaws.us-east-1.s3',
            VpcEndpointType='Gateway',
            RouteTableIds=[rt_id]
        )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate VPC endpoints locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs PrivateLink audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="VPC-Endpoint-Auditor: Audits VPC Endpoints and PrivateLink configurations."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual VPC endpoint testbed...")
            setup_mock_environment()

        auditor = PrivateLinkAuditor(profile=args.profile)
        report, risk_count = auditor.audit_vpc_endpoints()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} VPC endpoint governance risk(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on endpoint policy risks
        else:
            print("\n[+] SUCCESS: PrivateLink and VPC endpoint posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()