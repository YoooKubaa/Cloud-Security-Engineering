# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with Security Hub.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class SecurityHubAuditor:
    """
    (dev) Security Hub Auditor class. Evaluates AWS Security Hub enablement status,
    active security standards, and findings aggregation posture.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and Security Hub client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.sh = session.client('securityhub', region_name='us-east-1')

    def audit_security_hub(self):
        """
        (dev) Audits Security Hub posture:
        1. Checks if Security Hub is enabled in the account/region.
        2. Lists enabled security standards (CIS, AWS Foundational Best Practices).
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            # 1. Check if Security Hub is enabled
            try:
                hub_desc = self.sh.describe_hub()
                hub_arn = hub_desc.get('HubArn')
                if hub_arn:
                    findings.append({
                        "resource_type": "Security Hub",
                        "resource_name": "Account Security Hub",
                        "check": "Security Hub Enablement",
                        "status": "PASS",
                        "detail": f"AWS Security Hub is enabled and operational (HubArn: {hub_arn})."
                    })
                else:
                    risk_count += 1
                    findings.append({
                        "resource_type": "Security Hub",
                        "resource_name": "Account Security Hub",
                        "check": "Security Hub Enablement",
                        "status": "FAIL",
                        "detail": "AWS Security Hub is not enabled in this region."
                    })
            except ClientError as ce:
                error_code = ce.response.get('Error', {}).get('Code')
                if error_code in ['InvalidAccessException', 'AccessDeniedException', 'ResourceNotFoundException']:
                    risk_count += 1
                    findings.append({
                        "resource_type": "Security Hub",
                        "resource_name": "Account Security Hub",
                        "check": "Security Hub Enablement",
                        "status": "FAIL",
                        "detail": "AWS Security Hub is disabled or uninitialized in this region."
                    })
                else:
                    findings.append({
                        "resource_type": "Security Hub",
                        "resource_name": "Account Security Hub",
                        "check": "Security Hub Enablement Check",
                        "status": "ERROR",
                        "detail": str(ce)
                    })

            # 2. Check Enabled Standards
            try:
                standards_resp = self.sh.get_enabled_standards()
                enabled_standards = standards_resp.get('StandardsSubscriptions', [])
                
                if not enabled_standards:
                    findings.append({
                        "resource_type": "Security Hub Standards",
                        "resource_name": "Compliance Benchmarks",
                        "check": "Security Standards Subscriptions",
                        "status": "WARN",
                        "detail": "Security Hub has no compliance standards enabled (e.g., CIS AWS Foundations, AWS Best Practices)."
                    })
                else:
                    for std in enabled_standards:
                        std_arn = std.get('StandardsArn', 'UnknownStandard')
                        findings.append({
                            "resource_type": "Security Hub Standard",
                            "resource_name": std_arn.split('/')[-2] if '/' in std_arn else std_arn,
                            "check": "Compliance Benchmark Subscribed",
                            "status": "PASS",
                            "detail": f"Security standard benchmark is actively subscribed and evaluating posture."
                        })
            except ClientError:
                # If hub is disabled, standards check will fail gracefully
                pass

        except Exception as e:
            findings.append({
                "resource_type": "Security Hub Service",
                "resource_name": "Audit Execution",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "Security Hub Aggregation: Centralize findings from native tools, third-party CSPM (Prowler), and custom detections into a single compliance and incident dashboard.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto Security Hub environment with test scenarios:
    - Enables Security Hub locally in RAM.
    """
    sh = boto3.client('securityhub', region_name='us-east-1')
    sh.enable_security_hub(EnableDefaultStandards=True)


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate Security Hub locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs Security Hub audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Security-Hub-Auditor: Audits AWS Security Hub status and compliance standards."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual Security Hub testbed...")
            setup_mock_environment()

        auditor = SecurityHubAuditor(profile=args.profile)
        report, risk_count = auditor.audit_security_hub()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} Security Hub governance gap(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on missing aggregation
        else:
            print("\n[+] SUCCESS: Security Hub aggregation and compliance posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()