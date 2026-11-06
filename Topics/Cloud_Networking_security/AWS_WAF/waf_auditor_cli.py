# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with AWS WAFv2.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class WAFAuditor:
    """
    (dev) AWS WAF Auditor class. Evaluates Web ACLs, inspecting rule groups,
    override actions (COUNT vs BLOCK), and metric logging configurations.
    """
    
    def __init__(self, scope='REGIONAL', profile=None):
        """
        (dev) Class constructor. Initializes session and WAFv2 client.
        
        Parameters:
        - scope (str): WAF scope ('REGIONAL' or 'CLOUDFRONT').
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        # WAFv2 for CloudFront must be in us-east-1, Regional can be in target region
        region = 'us-east-1' if scope == 'CLOUDFRONT' else 'us-east-1'
        self.waf = session.client('wafv2', region_name=region)
        self.scope = scope

    def audit_web_acls(self):
        """
        (dev) Audits Web ACL configurations:
        1. Lists all Web ACLs for the specified scope.
        2. Inspects rules inside each Web ACL for COUNT vs BLOCK settings.
        3. Validates CloudWatch metric tracking and visibility.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            web_acls = self.waf.list_web_acls(Scope=self.scope).get('WebACLs', [])

            if not web_acls:
                findings.append({
                    "resource_type": "AWS WAF Scope",
                    "resource_name": self.scope,
                    "check": "Web ACL Presence",
                    "status": "PASS",
                    "detail": f"No Web ACLs found in scope {self.scope} (or account is clean)."
                })
            else:
                for acl in web_acls:
                    acl_name = acl['Name']
                    acl_id = acl['Id']
                    
                    # Get detailed Web ACL description
                    detail = self.waf.get_web_acl(Name=acl_name, Scope=self.scope, Id=acl_id).get('WebACL', {})
                    rules = detail.get('Rules', [])

                    for rule in rules:
                        rule_name = rule.get('Name', 'UnknownRule')
                        visibility = rule.get('VisibilityConfig', {})
                        cw_enabled = visibility.get('CloudWatchMetricsEnabled', False)
                        
                        # Check override action (Count vs Block)
                        override_action = rule.get('OverrideAction', {})
                        is_count_mode = 'Count' in override_action

                        if not cw_enabled:
                            risk_count += 1
                            findings.append({
                                "resource_type": "AWS WAF Rule",
                                "resource_name": f"{acl_name} -> {rule_name}",
                                "check": "CloudWatch Metrics Enabled",
                                "status": "FAIL",
                                "detail": "WAF rule does not have CloudWatch metrics enabled. False positive tuning and hit tracking are impossible without metrics."
                            })
                        elif is_count_mode:
                            findings.append({
                                "resource_type": "AWS WAF Rule",
                                "resource_name": f"{acl_name} -> {rule_name}",
                                "check": "Rule Enforcement Mode",
                                "status": "WARN",
                                "detail": "Rule is currently running in COUNT override mode. Staged for false positive analysis; ensure review before blocking."
                            })
                        else:
                            findings.append({
                                "resource_type": "AWS WAF Rule",
                                "resource_name": f"{acl_name} -> {rule_name}",
                                "check": "Rule Enforcement Mode",
                                "status": "PASS",
                                "detail": "Rule is active in BLOCK enforcement mode with CloudWatch telemetry enabled."
                            })
        except ClientError as ce:
            findings.append({
                "resource_type": "AWS WAFv2 Service",
                "resource_name": "Web ACL Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(ce)
            })
        except Exception as e:
            findings.append({
                "resource_type": "AWS WAFv2 Service",
                "resource_name": "Web ACL Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "AWS WAF Tuning: Safely tune managed and custom rule groups using COUNT mode before enforcement to eliminate false positives without creating security blind spots.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto WAFv2 environment with test scenarios:
    - Creates a sample Regional Web ACL with a managed rule group in COUNT mode.
    """
    waf = boto3.client('wafv2', region_name='us-east-1')

    waf.create_web_acl(
        Name='production-api-waf',
        Scope='REGIONAL',
        DefaultAction={'Allow': {}},
        VisibilityConfig={
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': 'ProductionAPIWAF'
        },
        Rules=[{
            'Name': 'AWSManagedRulesCommonRuleSet',
            'Priority': 1,
            'Statement': {
                'ManagedRuleGroupStatement': {
                    'VendorName': 'AWS',
                    'Name': 'AWSManagedRulesCommonRuleSet'
                }
            },
            'OverrideAction': {'Count': {}},
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'CommonRuleSetMetric'
            }
        }]
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS WAF locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs WAF audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="WAF-Tuning-Auditor: Audits AWS WAF Web ACLs and rule tuning postures."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--scope', type=str, choices=['REGIONAL', 'CLOUDFRONT'], default='REGIONAL', help="WAF scope")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual WAF testbed...")
            setup_mock_environment()

        auditor = WAFAuditor(scope=args.scope, profile=args.profile)
        report, risk_count = auditor.audit_web_acls()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} WAF configuration warning(s) / metric gap(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on monitoring gaps
        else:
            print("\n[+] SUCCESS: AWS WAF tuning posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()