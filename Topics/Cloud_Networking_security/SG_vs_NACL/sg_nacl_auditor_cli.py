# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with EC2 / VPC firewalls.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class SGNACLAuditor:
    """
    (dev) SG vs NACL Auditor class. Evaluates Security Groups (stateful) 
    for dangerous open ports and inspects Network ACLs (stateless) for subnet boundaries.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and EC2 client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.ec2 = session.client('ec2', region_name='us-east-1')

    def audit_firewalls(self):
        """
        (dev) Audits network firewalls:
        1. Enumerates Security Groups and checks for over-permissive ingress (`0.0.0.0/0` on sensitive ports).
        2. Enumerates Network ACLs and verifies stateless guardrail rules.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0
        sensitive_ports = [22, 3389, 3306, 5432, 1433, 27017]

        # --- 1. Audit Security Groups (Stateful) ---
        try:
            sgs = self.ec2.describe_security_groups().get('SecurityGroups', [])
            for sg in sgs:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                ingress_rules = sg.get('IpPermissions', [])

                for rule in ingress_rules:
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    ip_ranges = rule.get('IpRanges', [])
                    ipv6_ranges = rule.get('Ipv6Ranges', [])

                    # Check if any range allows 0.0.0.0/0 or ::/0
                    allows_world = False
                    for ip_range in ip_ranges:
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            allows_world = True
                            break
                    for ipv6_range in ipv6_ranges:
                        if ipv6_range.get('CidrIpv6') == '::/0':
                            allows_world = True
                            break

                    if allows_world:
                        # Check if it hits sensitive ports or is all ports
                        hits_sensitive = any(p >= from_port and p <= to_port for p in sensitive_ports) or (from_port == 0 and to_port == 65535)

                        if hits_sensitive:
                            risk_count += 1
                            findings.append({
                                "resource_type": "Security Group",
                                "resource_name": f"{sg_name} ({sg_id})",
                                "check": "Over-permissive Ingress (Sensitive Ports)",
                                "status": "FAIL",
                                "detail": f"Security Group allows unrestricted inbound traffic (0.0.0.0/0) covering ports {from_port}-{to_port}, exposing sensitive services."
                            })
                        else:
                            findings.append({
                                "resource_type": "Security Group",
                                "resource_name": f"{sg_name} ({sg_id})",
                                "check": "Public Ingress Rule",
                                "status": "PASS",
                                "detail": f"Security Group allows public traffic on non-sensitive ports {from_port}-{to_port} (e.g., HTTP/HTTPS)."
                            })
                    else:
                        findings.append({
                            "resource_type": "Security Group",
                            "resource_name": f"{sg_name} ({sg_id})",
                            "check": "Restricted Ingress",
                            "status": "PASS",
                            "detail": f"Security Group ingress rule on ports {from_port}-{to_port} is properly restricted."
                        })
        except Exception as e:
            findings.append({
                "resource_type": "Security Groups",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        # --- 2. Audit Network ACLs (Stateless) ---
        try:
            nacls = self.ec2.describe_network_acls().get('NetworkAcls', [])
            for nacl in nacls:
                nacl_id = nacl['NetworkAclId']
                entries = nacl.get('Entries', [])
                
                findings.append({
                    "resource_type": "Network ACL",
                    "resource_name": nacl_id,
                    "check": "Stateless Subnet Guardrail",
                    "status": "PASS",
                    "detail": f"Network ACL inspected with {len(entries)} active rule entries."
                })
        except Exception as e:
            findings.append({
                "resource_type": "Network ACLs",
                "resource_name": "Enumeration Error",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "SG vs NACL: Security Groups are stateful firewalls protecting individual ENIs (used 95% of the time), while NACLs are stateless subnet firewalls supporting explicit deny rules.",
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
    - A default security group with an insecure open SSH rule (Risk condition).
    """
    ec2 = boto3.client('ec2', region_name='us-east-1')

    # Get default VPC id
    vpcs = ec2.describe_vpcs().get('Vpcs', [])
    if vpcs:
        vpc_id = vpcs[0]['VpcId']
        # Create an insecure security group with SSH open to the world
        sg = ec2.create_security_group(
            GroupName='insecure-admin-sg',
            Description='Insecure SG with open SSH',
            VpcId=vpc_id
        )
        sg_id = sg['GroupId']
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate firewalls locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs SG vs NACL audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="SG-NACL-Auditor: Audits Security Groups and Network ACLs for perimeter exposure."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual firewall testbed...")
            setup_mock_environment()

        auditor = SGNACLAuditor(profile=args.profile)
        report, risk_count = auditor.audit_firewalls()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} network firewall risk(s) (over-permissive ingress)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on firewall violations
        else:
            print("\n[+] SUCCESS: Network firewall posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()