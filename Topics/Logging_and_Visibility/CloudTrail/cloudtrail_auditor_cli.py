# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with CloudTrail.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class CloudTrailAuditor:
    """
    (dev) CloudTrail Auditor class. Evaluates CloudTrail trails across multi-region coverage,
    log file validation, and active logging status.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and CloudTrail client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.ct = session.client('cloudtrail', region_name='us-east-1')

    def audit_cloudtrail(self):
        """
        (dev) Audits CloudTrail posture:
        1. Describes all trails in the account.
        2. Checks multi-region trail setting.
        3. Checks log file validation setting.
        4. Checks if logging is actively running.
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            trails_resp = self.ct.describe_trails(includeShadowTrails=False)
            trail_list = trails_resp.get('trailList', [])

            if not trail_list:
                risk_count += 1
                findings.append({
                    "resource_type": "CloudTrail Service",
                    "resource_name": "Account Trails",
                    "check": "CloudTrail Presence",
                    "status": "FAIL",
                    "detail": "No CloudTrail trails found in the account. API telemetry is completely unmonitored."
                })
            else:
                for trail in trail_list:
                    trail_name = trail.get('Name')
                    trail_arn = trail.get('TrailARN')
                    is_multi_region = trail.get('IsMultiRegionTrail', False)
                    log_validation = trail.get('LogFileValidationEnabled', False)

                    # Check logging status
                    try:
                        status = self.ct.get_trail_status(Name=trail_arn)
                        is_logging = status.get('IsLogging', False)
                    except ClientError:
                        is_logging = False

                    # 1. Multi-Region Check
                    if not is_multi_region:
                        risk_count += 1
                        findings.append({
                            "resource_type": "CloudTrail",
                            "resource_name": trail_name,
                            "check": "Multi-Region Coverage",
                            "status": "FAIL",
                            "detail": "CloudTrail is single-region only. Attackers can execute API calls in unmonitored regions undetected."
                        })
                    else:
                        findings.append({
                            "resource_type": "CloudTrail",
                            "resource_name": trail_name,
                            "check": "Multi-Region Coverage",
                            "status": "PASS",
                            "detail": "CloudTrail is configured as a multi-region trail."
                        })

                    # 2. Log File Validation Check
                    if not log_validation:
                        risk_count += 1
                        findings.append({
                            "resource_type": "CloudTrail",
                            "resource_name": trail_name,
                            "check": "Log File Validation",
                            "status": "FAIL",
                            "detail": "Log file validation is disabled. Cryptographic integrity hash-chaining is required to detect log tampering."
                        })
                    else:
                        findings.append({
                            "resource_type": "CloudTrail",
                            "resource_name": trail_name,
                            "check": "Log File Validation",
                            "status": "PASS",
                            "detail": "Log file validation is enabled with cryptographic hash verification."
                        })

                    # 3. Active Logging Status Check
                    if not is_logging:
                        risk_count += 1
                        findings.append({
                            "resource_type": "CloudTrail",
                            "resource_name": trail_name,
                            "check": "Active Logging State",
                            "status": "FAIL",
                            "detail": "CloudTrail logging is STOPPED (StopLogging event detected or trail paused)."
                        })
                    else:
                        findings.append({
                            "resource_type": "CloudTrail",
                            "resource_name": trail_name,
                            "check": "Active Logging State",
                            "status": "PASS",
                            "detail": "CloudTrail logging is active."
                        })
        except Exception as e:
            findings.append({
                "resource_type": "CloudTrail Service",
                "resource_name": "Trail Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "CloudTrail Visibility: Capture every API call across multi-region environments with cryptographic log file validation enabled to ensure tamper-proof incident forensics.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto CloudTrail environment with test scenarios:
    - Creates a fully compliant multi-region trail with log validation.
    """
    ct = boto3.client('cloudtrail', region_name='us-east-1')
    s3 = boto3.client('s3', region_name='us-east-1')

    # Create bucket for trail logs
    s3.create_bucket(Bucket='mock-audit-logs-bucket')

    # Create secure multi-region trail
    ct.create_trail(
        Name='prod-audit-trail',
        S3BucketName='mock-audit-logs-bucket',
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True
    )
    ct.start_logging(Name='prod-audit-trail')


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate CloudTrail locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs CloudTrail audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="CloudTrail-Auditor: Audits AWS CloudTrail multi-region status and log integrity."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual CloudTrail testbed...")
            setup_mock_environment()

        auditor = CloudTrailAuditor(profile=args.profile)
        report, risk_count = auditor.audit_cloudtrail()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} CloudTrail security/integrity gap(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on logging vulnerabilities
        else:
            print("\n[+] SUCCESS: CloudTrail logging and integrity posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()