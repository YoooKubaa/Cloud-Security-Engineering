# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with EC2 VPC Flow Logs.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class VPCFlowLogsAuditor:
    """
    (dev) VPC Flow Logs Auditor class. Evaluates VPC network telemetry coverage,
    checking whether flow logs are active across all customer and custom VPCs.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and EC2 client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.ec2 = session.client('ec2', region_name='us-east-1')

    def audit_flow_logs(self):
        """
        (dev) Audits VPC Flow Logs posture:
        1. Enumerates all active VPCs in the account/region.
        2. Queries existing Flow Logs and maps them to their target VPC IDs.
        3. Flags unmonitored VPCs lacking active flow logs.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            # 1. Get all VPCs
            vpcs = self.ec2.describe_vpcs().get('Vpcs', [])
            
            # 2. Get all Flow Logs in the region
            flow_logs = self.ec2.describe_flow_logs().get('FlowLogs', [])
            monitored_vpc_ids = set()
            
            for fl in flow_logs:
                # Flow logs can be attached to VPC, Subnet, or ENI. Check resource-id if it's a VPC.
                resource_id = fl.get('ResourceId', '')
                status = fl.get('FlowLogStatus', '')
                if resource_id.startswith('vpc-') and status == 'ACTIVE':
                    monitored_vpc_ids.add(resource_id)

            # 3. Evaluate each VPC
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                is_default = vpc.get('IsDefault', False)

                if vpc_id in monitored_vpc_ids:
                    findings.append({
                        "resource_type": "VPC",
                        "resource_name": vpc_id,
                        "check": "VPC Flow Logs Active",
                        "status": "PASS",
                        "detail": f"VPC {vpc_id} has active VPC Flow Logs enabled."
                    })
                else:
                    risk_count += 1
                    findings.append({
                        "resource_type": "VPC",
                        "resource_name": vpc_id,
                        "check": "VPC Flow Logs Active",
                        "status": "FAIL",
                        "detail": f"VPC {vpc_id} does not have VPC Flow Logs enabled. Network traffic is unmonitored."
                    })
        except Exception as e:
            findings.append({
                "resource_type": "EC2 / VPC Service",
                "resource_name": "Flow Logs Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "VPC Flow Logs: Capture network traffic metadata (ACCEPT/REJECT) across VPCs to detect lateral movement, unauthorized port scans, and security anomalies.",
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
    - Creates a custom VPC WITH flow logs enabled.
    - Leaves the default VPC WITHOUT flow logs enabled (Risk condition).
    """
    ec2 = boto3.client('ec2', region_name='us-east-1')

    # Create a monitored custom VPC
    custom_vpc = ec2.create_vpc(CidrBlock='10.1.0.0/16')
    custom_vpc_id = custom_vpc['Vpc']['VpcId']

    # Enable flow logs on the custom VPC
    ec2.create_flow_logs(
        ResourceIds=[custom_vpc_id],
        ResourceType='VPC',
        TrafficType='ALL',
        LogDestinationType='cloud-watch-logs',
        LogGroupName='/aws/vpc/flowlogs'
    )

    # Note: Moto default VPC will be present and unmonitored, triggering a FAIL finding.


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate VPC flow logs locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs VPC flow logs audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="VPC-Flow-Logs-Auditor: Audits VPC network telemetry coverage via Flow Logs."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual flow logs testbed...")
            setup_mock_environment()

        auditor = VPCFlowLogsAuditor(profile=args.profile)
        report, risk_count = auditor.audit_flow_logs()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} unmonitored VPC(s) without Flow Logs!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on unmonitored networks
        else:
            print("\n[+] SUCCESS: VPC Flow Logs telemetry coverage fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()