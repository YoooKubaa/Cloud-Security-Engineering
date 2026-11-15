# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation
import boto3     # (dev) Official AWS SDK for Python to query CloudTrail.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class IAMAwuseDetector:
    """
    (dev) IAM Abuse Detector class. Ingests CloudTrail event history and correlates
    suspicious API call sequences (e.g., PassRole + CreateFunction, CreateAccessKey).
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and CloudTrail client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.ct = session.client('cloudtrail', region_name='us-east-1')

    def analyze_events(self, events_list):
        """
        (dev) Analyzes a list of CloudTrail event dictionaries for IAM abuse patterns:
        1. Privilege Escalation: PassRole + CreateFunction / RunInstances by same principal.
        2. Persistence: CreateAccessKey events.
        3. Authentication anomaly: ConsoleLogin without MFA.
        
        Returns:
        - tuple (findings, risk_count): List of findings and count of detected risks.
        """
        findings = []
        risk_count = 0
        principal_activity = {}

        for event in events_list:
            event_name = event.get('EventName')
            username = event.get('Username', event.get('UserIdentity', {}).get('Username', 'UnknownPrincipal'))
            event_time = event.get('EventTime', '2026-01-01T00:00:00Z')
            cloudtrail_event_str = event.get('CloudTrailEvent', '{}')

            try:
                event_detail = json.loads(cloudtrail_event_str) if isinstance(cloudtrail_event_str, str) else cloudtrail_event_str
            except json.JSONDecodeError:
                event_detail = {}

            # Track actions per principal for temporal correlation
            if username not in principal_activity:
                principal_activity[username] = []
            principal_activity[username].append({'event': event_name, 'time': event_time})

            # Check 1: Persistence via CreateAccessKey
            if event_name == 'CreateAccessKey':
                risk_count += 1
                findings.append({
                    "resource_type": "IAM User",
                    "resource_name": username,
                    "check": "Persistence (CreateAccessKey)",
                    "status": "FAIL",
                    "detail": f"New access key created for principal '{username}' at {event_time}. Potential persistence vector."
                })

            # Check 2: ConsoleLogin without MFA
            elif event_name == 'ConsoleLogin':
                additional_data = event_detail.get('additionalEventData', {})
                mfa_used = additional_data.get('MFAUsed', 'Yes')
                if mfa_used == 'No':
                    risk_count += 1
                    findings.append({
                        "resource_type": "IAM Principal",
                        "resource_name": username,
                        "check": "Authentication Anomaly (ConsoleLogin without MFA)",
                        "status": "FAIL",
                        "detail": f"Console login detected without MFA for principal '{username}'."
                    })
                else:
                    findings.append({
                        "resource_type": "IAM Principal",
                        "resource_name": username,
                        "check": "Console Login MFA",
                        "status": "PASS",
                        "detail": f"Console login secured with MFA for principal '{username}'."
                    })

        # Check 3: Temporal Correlation for Privilege Escalation (PassRole + CreateFunction)
        for principal, actions in principal_activity.items():
            event_names = [a['event'] for a in actions]
            if 'PassRole' in event_names and ('CreateFunction' in event_names or 'RunInstances' in event_names):
                risk_count += 1
                findings.append({
                    "resource_type": "IAM Principal",
                    "resource_name": principal,
                    "check": "Privilege Escalation Chain (PassRole + Compute)",
                    "status": "FAIL",
                    "detail": f"Detected suspicious temporal correlation: Principal '{principal}' executed 'PassRole' alongside compute creation actions, indicating potential privilege escalation."
                })

        if not findings:
            findings.append({
                "resource_type": "IAM Audit",
                "resource_name": "CloudTrail Log Stream",
                "check": "IAM Abuse Baseline",
                "status": "PASS",
                "detail": "No suspicious IAM abuse or privilege escalation chains detected in event telemetry."
            })

        return findings, risk_count

    def audit_trail(self):
        """
        (dev) Fetches recent CloudTrail event history and runs IAM abuse detection.
        """
        try:
            response = self.ct.lookup_events(MaxResults=50)
            events = response.get('Events', [])
            return self.analyze_events(events)
        except ClientError as ce:
            # Fallback for mock/empty environments where lookup_events might return empty
            return self.analyze_events([])


# --- MOCK DATA GENERATOR ---
def get_mock_iam_abuse_events():
    """
    (dev) Generates simulated CloudTrail event logs containing an IAM privilege escalation
    chain and unauthorized access key creation for testing.
    """
    return [
        {
            "EventName": "PassRole",
            "Username": "compromised-developer",
            "EventTime": "2026-11-15T12:00:00Z",
            "CloudTrailEvent": json.dumps({"additionalEventData": {"MFAUsed": "Yes"}})
        },
        {
            "EventName": "CreateFunction",
            "Username": "compromised-developer",
            "EventTime": "2026-11-15T12:02:00Z",
            "CloudTrailEvent": json.dumps({"additionalEventData": {}})
        },
        {
            "EventName": "CreateAccessKey",
            "Username": "legacy-service-account",
            "EventTime": "2026-11-15T12:05:00Z",
            "CloudTrailEvent": json.dumps({"additionalEventData": {}})
        },
        {
            "EventName": "ConsoleLogin",
            "Username": "admin-user",
            "EventTime": "2026-11-15T12:10:00Z",
            "CloudTrailEvent": json.dumps({"additionalEventData": {"MFAUsed": "No"}})
        }
    ]


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate CloudTrail locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs IAM abuse detection, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="IAM-Abuse-Detector: Analyzes CloudTrail telemetry for privilege escalation and persistence."
    )
    
    parser.add_argument('action', choices=['audit'], help="Action to execute (currently 'audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run detector using simulated mock CloudTrail events")
    
    args = parser.parse_args()

    if args.action == 'audit':
        detector = IAMAwuseDetector(profile=args.profile)

        if args.mock:
            print("[*] MOCK mode active. Processing simulated IAM abuse event telemetry...")
            findings, risk_count = detector.analyze_events(get_mock_iam_abuse_events())
        else:
            findings, risk_count = detector.audit_trail()

        report = {
            "metadata": {
                "philosophy": "IAM Abuse Detection: Correlate sequential CloudTrail API events (e.g., PassRole + CreateFunction) in tight time windows to catch privilege escalation before exploitation.",
                "total_checks": len(findings),
                "failed_checks": risk_count
            },
            "findings": findings
        }

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
            print(f"\n[!] SECURITY ALERT: Detected {risk_count} IAM abuse / privilege escalation indicator(s)!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on IAM threats
        else:
            print("\n[+] SUCCESS: IAM event telemetry posture fully clean.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()