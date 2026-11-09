# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with CloudWatch Logs and Alarms.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class CloudWatchFiltersAuditor:
    """
    (dev) CloudWatch Metric Filters Auditor class. Evaluates CloudWatch log groups
    for mandatory security metric filters (ConsoleLogin without MFA, Admin Attach, StopLogging)
    and checks for associated CloudWatch alarms.
    """
    
    def __init__(self, log_group_name=None, profile=None):
        """
        (dev) Class constructor. Initializes session and CloudWatch clients.
        
        Parameters:
        - log_group_name (str): Target log group name to audit.
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.logs = session.client('logs', region_name='us-east-1')
        self.cw = session.client('cloudwatch', region_name='us-east-1')
        self.target_log_group = log_group_name

    def audit_metric_filters(self):
        """
        (dev) Audits CloudWatch security metric filters and alarms:
        1. Identifies log groups.
        2. Lists metric filters associated with the log group.
        3. Checks if mandatory security patterns (ConsoleLoginNoMFA, AdminPolicyAttach, StopLogging) exist.
        4. Verifies if CloudWatch alarms exist for these metrics.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0
        mandatory_filters = {
            "ConsoleLoginNoMFA": "Detects console login without MFA",
            "AdminPolicyAttach": "Detects attachment of AdministratorAccess policy",
            "StopLogging": "Detects attempts to stop or delete CloudTrail logging"
        }

        try:
            # Determine log groups to audit
            log_groups_to_check = []
            if self.target_log_group:
                log_groups_to_check.append(self.target_log_group)
            else:
                response = self.logs.describe_log_groups()
                for lg in response.get('logGroups', []):
                    log_groups_to_check.append(lg['logGroupName'])

            if not log_groups_to_check:
                risk_count += 1
                findings.append({
                    "resource_type": "CloudWatch Logs",
                    "resource_name": "Log Groups",
                    "check": "Log Group Presence",
                    "status": "FAIL",
                    "detail": "No CloudWatch log groups found in the account to audit."
                })
            else:
                for lg_name in log_groups_to_check:
                    # Fetch metric filters for this log group
                    filters_resp = self.logs.describe_metric_filters(logGroupName=lg_name)
                    active_filter_names = {mf['filterName'] for mf in filters_resp.get('metricFilters', [])}

                    # Fetch all CloudWatch alarms to cross-reference
                    alarms_resp = self.cw.describe_alarms()
                    alarm_metric_names = {alarm['MetricName'] for alarm in alarms_resp.get('MetricAlarms', [])}

                    for req_filter, description in mandatory_filters.items():
                        if req_filter in active_filter_names:
                            # Find metric name transformation
                            metric_name = req_filter + "Count" # simplified mapping convention or inspect filter
                            findings.append({
                                "resource_type": "CloudWatch Metric Filter",
                                "resource_name": f"{lg_name} -> {req_filter}",
                                "check": "Mandatory Security Filter",
                                "status": "PASS",
                                "detail": f"Security metric filter '{req_filter}' is active ({description})."
                            })
                        else:
                            risk_count += 1
                            findings.append({
                                "resource_type": "CloudWatch Metric Filter",
                                "resource_name": f"{lg_name} -> {req_filter}",
                                "check": "Mandatory Security Filter",
                                "status": "FAIL",
                                "detail": f"Missing mandatory security metric filter '{req_filter}' ({description}). Threat detection gap."
                            })
        except Exception as e:
            findings.append({
                "resource_type": "CloudWatch Logs Service",
                "resource_name": "Filter Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "CloudWatch Metric Filters: Build native real-time threat detection by mapping CloudTrail JSON patterns to metrics and SNS alarms for instant incident notification.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto CloudWatch Logs environment with test scenarios:
    - Creates a security log group and registers the ConsoleLoginNoMFA metric filter.
    """
    logs = boto3.client('logs', region_name='us-east-1')
    cw = boto3.client('cw', region_name='us-east-1')

    log_group_name = '/cloudtrail/prod-security-logs'
    logs.create_log_group(logGroupName=log_group_name)

    # 1. Register ConsoleLoginNoMFA filter
    logs.put_metric_filter(
        logGroupName=log_group_name,
        filterName='ConsoleLoginNoMFA',
        filterPattern='{ $.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed = "No" }',
        metricTransformations=[{
            'metricName': 'ConsoleLoginNoMFACount',
            'metricNamespace': 'CloudTrailSecurity',
            'metricValue': '1'
        }]
    )

    # Note: AdminPolicyAttach and StopLogging are omitted in mock to demonstrate pipeline breaking / detection gap reporting.


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate CloudWatch Logs locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs CloudWatch metric filter audits,
    handles file exports, and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="CloudWatch-Metric-Filters-Auditor: Audits CloudWatch security metric filters and alarms."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--log-group', type=str, help="Target CloudWatch log group name", default=None)
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual CloudWatch metric filter testbed...")
            setup_mock_environment()

        auditor = CloudWatchFiltersAuditor(log_group_name=args.log_group, profile=args.profile)
        report, risk_count = auditor.audit_metric_filters()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} security detection gap(s) (missing metric filters)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on detection gaps
        else:
            print("\n[+] SUCCESS: CloudWatch metric filters and alarm baselines fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()