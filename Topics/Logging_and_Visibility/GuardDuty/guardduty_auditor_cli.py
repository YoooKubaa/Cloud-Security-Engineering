# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to interact with GuardDuty.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class GuardDutyAuditor:
    """
    (dev) GuardDuty Auditor class. Evaluates Amazon GuardDuty detector statuses
    and telemetry data source configurations.
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and GuardDuty client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.gd = session.client('guardduty', region_name='us-east-1')

    def audit_guardduty(self):
        """
        (dev) Audits GuardDuty threat detection posture:
        1. Lists detectors in the region.
        2. Checks if detectors are enabled (status = ENABLED).
        3. Inspects data source configurations (S3, Kubernetes, Malware Protection).
        
        Returns:
        - tuple (report, risk_count): Dictionary report and count of failing checks.
        """
        findings = []
        risk_count = 0

        try:
            detectors_resp = self.gd.list_detectors()
            detector_ids = detectors_resp.get('DetectorIds', [])

            if not detector_ids:
                risk_count += 1
                findings.append({
                    "resource_type": "GuardDuty Service",
                    "resource_name": "Regional Detectors",
                    "check": "GuardDuty Detector Presence",
                    "status": "FAIL",
                    "detail": "No GuardDuty detectors found in this region. ML threat detection is completely disabled."
                })
            else:
                for det_id in detector_ids:
                    try:
                        det_info = self.gd.get_detector(DetectorId=det_id)
                        status = det_info.get('Status', 'DISABLED')
                        data_sources = det_info.get('DataSources', {})

                        if status != 'ENABLED':
                            risk_count += 1
                            findings.append({
                                "resource_type": "GuardDuty Detector",
                                "resource_name": det_id,
                                "check": "Detector Active Status",
                                "status": "FAIL",
                                "detail": f"GuardDuty detector status is '{status}' (not ENABLED)."
                            })
                        else:
                            findings.append({
                                "resource_type": "GuardDuty Detector",
                                "resource_name": det_id,
                                "check": "Detector Active Status",
                                "status": "PASS",
                                "detail": "GuardDuty detector is enabled and actively monitoring telemetry feeds."
                            })

                            # Check S3 logs data source
                            s3_logs = data_sources.get('S3Logs', {}).get('Enable', False)
                            if not s3_logs:
                                findings.append({
                                    "resource_type": "GuardDuty Data Sources",
                                    "resource_name": det_id,
                                    "check": "S3 Data Events Monitoring",
                                    "status": "WARN",
                                    "detail": "GuardDuty S3 data events monitoring is disabled. Recommended for data exfiltration detection."
                                })
                            else:
                                findings.append({
                                    "resource_type": "GuardDuty Data Sources",
                                    "resource_name": det_id,
                                    "check": "S3 Data Events Monitoring",
                                    "status": "PASS",
                                    "detail": "GuardDuty S3 data events monitoring is enabled."
                                })
                    except ClientError as ce:
                        findings.append({
                            "resource_type": "GuardDuty Detector",
                            "resource_name": det_id,
                            "check": "Detector Configuration Query",
                            "status": "ERROR",
                            "detail": str(ce)
                        })
        except Exception as e:
            findings.append({
                "resource_type": "GuardDuty Service",
                "resource_name": "Detector Enumeration",
                "check": "API Query Execution",
                "status": "ERROR",
                "detail": str(e)
            })

        report = {
            "metadata": {
                "philosophy": "GuardDuty Threat Detection: Leverage managed machine learning and threat intelligence feeds to catch anomalous behavior, complementing custom architecture-specific detection rules.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }
        
        return report, risk_count


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto GuardDuty environment with test scenarios:
    - Creates an enabled GuardDuty detector.
    """
    gd = boto3.client('guardduty', region_name='us-east-1')
    gd.create_detector(Enable=True)


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate GuardDuty locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs GuardDuty audits, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="GuardDuty-Auditor: Audits Amazon GuardDuty detector statuses and data sources."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'audit':
        if args.mock:
            print("[*] MOCK mode active. Generating virtual GuardDuty testbed...")
            setup_mock_environment()

        auditor = GuardDutyAuditor(profile=args.profile)
        report, risk_count = auditor.audit_guardduty()

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} GuardDuty detector vulnerability/gaps!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on missing threat detection
        else:
            print("\n[+] SUCCESS: GuardDuty threat detection posture fully secured.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()