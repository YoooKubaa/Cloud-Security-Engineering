# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to query CloudTrail.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.


class TrailTamperingDetector:
    """
    (dev) Trail Tampering Detector class. Scans CloudTrail event streams for
    Defense Evasion indicators (MITRE ATT&CK T1562.008): StopLogging, DeleteTrail, and UpdateTrail.
    """

    TAMPER_EVENTS = {"StopLogging", "DeleteTrail", "UpdateTrail"}

    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes AWS session and CloudTrail client.

        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.ct = session.client('cloudtrail', region_name='us-east-1')

    def analyze_events(self, events_list):
        """
        (dev) Evaluates CloudTrail events for tampering patterns and subtle configuration downgrades.

        Returns:
        - tuple (findings, risk_count): List of structured findings and total count of detections.
        """
        findings = []
        risk_count = 0

        for event in events_list:
            event_name = event.get('EventName')
            if event_name not in self.TAMPER_EVENTS:
                continue

            actor = event.get('Username', 'UnknownPrincipal')
            event_time = str(event.get('EventTime', 'UnknownTime'))
            raw_detail = event.get('CloudTrailEvent', '{}')

            try:
                detail = json.loads(raw_detail) if isinstance(raw_detail, str) else raw_detail
            except json.JSONDecodeError:
                detail = {}

            req_params = detail.get('requestParameters', {}) or {}
            trail_name = req_params.get('name', req_params.get('Name', 'UnknownTrail'))

            if event_name in ("StopLogging", "DeleteTrail"):
                risk_count += 1
                findings.append({
                    "resource_type": "CloudTrail",
                    "resource_name": trail_name,
                    "actor": actor,
                    "event_name": event_name,
                    "mitre_id": "T1562.008",
                    "severity": "CRITICAL",
                    "status": "FAIL",
                    "detail": (
                        f"CRITICAL DEFENSE EVASION: Principal '{actor}' executed '{event_name}' "
                        f"on trail '{trail_name}' at {event_time}. Immediate on-call escalation required."
                    )
                })

            elif event_name == "UpdateTrail":
                risk_count += 1
                downgrades = []
                if req_params.get('isMultiRegionTrail') is False or req_params.get('IsMultiRegionTrail') is False:
                    downgrades.append("disabled Multi-Region coverage")
                if req_params.get('enableLogFileValidation') is False or req_params.get('EnableLogFileValidation') is False:
                    downgrades.append("disabled Cryptographic Log File Validation")

                downgrade_note = (
                    f" Specific degradation detected: {', '.join(downgrades)}."
                    if downgrades
                    else " Trail parameters modified; inspect configuration diff immediately."
                )

                findings.append({
                    "resource_type": "CloudTrail",
                    "resource_name": trail_name,
                    "actor": actor,
                    "event_name": event_name,
                    "mitre_id": "T1562.008",
                    "severity": "HIGH" if not downgrades else "CRITICAL",
                    "status": "FAIL",
                    "detail": (
                        f"DEFENSE EVASION: Principal '{actor}' executed 'UpdateTrail' on '{trail_name}' "
                        f"at {event_time}.{downgrade_note}"
                    )
                })

        if not findings:
            findings.append({
                "resource_type": "CloudTrail",
                "resource_name": "Account Trails",
                "actor": "N/A",
                "event_name": "None",
                "mitre_id": "T1562.008",
                "severity": "INFO",
                "status": "PASS",
                "detail": "No StopLogging, DeleteTrail, or UpdateTrail tampering events detected in recent telemetry."
            })

        return findings, risk_count

    def audit_trail(self):
        """
        (dev) Queries live CloudTrail LookupEvents API and evaluates tampering indicators.
        """
        try:
            response = self.ct.lookup_events(MaxResults=50)
            events = response.get('Events', [])
            return self.analyze_events(events)
        except ClientError as ce:
            return [{
                "resource_type": "CloudTrail Service",
                "resource_name": "LookupEvents API",
                "actor": "N/A",
                "event_name": "API_ERROR",
                "mitre_id": "T1562.008",
                "severity": "ERROR",
                "status": "ERROR",
                "detail": str(ce)
            }], 1


# --- MOCK DATA GENERATOR ---
def get_mock_tampering_events():
    """
    (dev) Simulates a realistic multi-vector CloudTrail tampering sequence:
    1. Subtle downgrade via UpdateTrail (turning off Multi-Region & Log File Validation).
    2. Overt blinding via StopLogging.
    3. Permanent erasure via DeleteTrail.
    """
    return [
        {
            "EventName": "UpdateTrail",
            "Username": "compromised-devops-role",
            "EventTime": "2026-11-16T20:05:12Z",
            "CloudTrailEvent": json.dumps({
                "requestParameters": {
                    "name": "prod-organization-trail",
                    "isMultiRegionTrail": False,
                    "enableLogFileValidation": False
                }
            })
        },
        {
            "EventName": "StopLogging",
            "Username": "compromised-devops-role",
            "EventTime": "2026-11-16T20:06:01Z",
            "CloudTrailEvent": json.dumps({
                "requestParameters": {
                    "name": "prod-organization-trail"
                }
            })
        },
        {
            "EventName": "DeleteTrail",
            "Username": "attacker-persistence-user",
            "EventTime": "2026-11-16T20:09:44Z",
            "CloudTrailEvent": json.dumps({
                "requestParameters": {
                    "name": "backup-security-trail"
                }
            })
        }
    ]


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate CloudTrail locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI flags, executes tampering detection, exports JSON reports,
    and returns CI/CD exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Trail-Tampering-Detector: Detects CloudTrail Defense Evasion (MITRE T1562.008)."
    )

    parser.add_argument('action', choices=['audit'], help="Action to execute ('audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run detector using simulated tampering telemetry")

    args = parser.parse_args()

    if args.action == 'audit':
        detector = TrailTamperingDetector(profile=args.profile)

        if args.mock:
            print("[*] MOCK mode active. Analyzing simulated CloudTrail tampering telemetry...")
            findings, risk_count = detector.analyze_events(get_mock_tampering_events())
        else:
            findings, risk_count = detector.audit_trail()

        report = {
            "metadata": {
                "philosophy": (
                    "Trail Tampering Detection (MITRE T1562.008): Adversaries disable or degrade logging "
                    "before executing noisy actions. Detect StopLogging, DeleteTrail, and subtle UpdateTrail "
                    "downgrades immediately."
                ),
                "mitre_technique": "T1562.008 - Impair Defenses: Disable or Modify Cloud Logs",
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
            print(
                f"\n[!] CRITICAL SECURITY ALERT: Detected {risk_count} CloudTrail tampering / defense evasion event(s)!",
                file=sys.stderr
            )
            sys.exit(1)
        else:
            print("\n[+] SUCCESS: No CloudTrail tampering activity detected.", file=sys.stderr)
            sys.exit(0)


if __name__ == "__main__":
    main()