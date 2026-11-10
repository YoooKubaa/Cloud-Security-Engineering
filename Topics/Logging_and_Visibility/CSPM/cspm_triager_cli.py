# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.

class CSPMTriager:
    """
    (dev) CSPM Prowler Finding Triager class. Ingests security posture scan reports,
    evaluates findings against exception rules (Fix vs Accept Risk), and enforces pipeline gates.
    """
    
    def __init__(self, report_path=None):
        """
        (dev) Class constructor. Initializes report path and exception register.
        
        Parameters:
        - report_path (str, optional): Path to Prowler JSON output report.
        """
        self.report_path = report_path
        # Example organization-wide accepted risk exceptions (Resource ARN / ID -> Justification)
        self.accepted_exceptions = {
            "arn:aws:s3:::public-assets-cdn": "Intentional public CDN bucket for static web assets."
        }

    def process_findings(self, findings_data):
        """
        (dev) Processes and triages a list of CSPM findings:
        1. Evaluates severity (CRITICAL, HIGH, MEDIUM, LOW).
        2. Checks against accepted risk exceptions.
        3. Assigns triage decision: FIX, ACCEPT_RISK, or FALSE_POSITIVE.
        
        Returns:
        - tuple (triage_report, actionable_failure_count): Summary report and count of unmitigated risks.
        """
        results = []
        actionable_failures = 0

        for finding in findings_data:
            finding_id = finding.get('finding_id', 'unknown_check')
            resource = finding.get('resource_arn', finding.get('resource', 'unknown_resource'))
            severity = finding.get('severity', 'MEDIUM').upper()
            title = finding.get('title', 'Security Misconfiguration')

            # Check if resource has an accepted risk exception
            if resource in self.accepted_exceptions:
                results.append({
                    "finding_id": finding_id,
                    "resource": resource,
                    "severity": severity,
                    "title": title,
                    "decision": "ACCEPT_RISK",
                    "rationale": f"Exception matched: {self.accepted_exceptions[resource]}"
                })
            else:
                if severity in ['CRITICAL', 'HIGH']:
                    actionable_failures += 1
                    results.append({
                        "finding_id": finding_id,
                        "resource": resource,
                        "severity": severity,
                        "title": title,
                        "decision": "FIX",
                        "rationale": f"High-severity posture failure ({severity}) requires immediate remediation."
                    })
                else:
                    results.append({
                        "finding_id": finding_id,
                        "resource": resource,
                        "severity": severity,
                        "title": title,
                        "decision": "REVIEW",
                        "rationale": f"Medium/Low severity finding ({severity}). Scheduled for backlog review."
                    })

        triage_report = {
            "metadata": {
                "philosophy": "CSPM Triage: Separate static posture configuration misconfigurations from runtime behavior, applying intelligent exception governance (Fix vs Accept Risk).",
                "total_findings": len(findings_data),
                "actionable_failures": actionable_failures
            },
            "triage_results": results
        }

        return triage_report, actionable_failures


# --- MOCK DATA GENERATOR ---
def get_mock_prowler_findings():
    """
    (dev) Generates simulated Prowler JSON findings for testing and mock mode execution.
    """
    return [
        {
            "finding_id": "s3_bucket_public_access",
            "resource_arn": "arn:aws:s3:::customer-data-vault",
            "severity": "CRITICAL",
            "title": "S3 bucket allows public read access"
        },
        {
            "finding_id": "s3_bucket_public_access",
            "resource_arn": "arn:aws:s3:::public-assets-cdn",
            "severity": "HIGH",
            "title": "S3 bucket lacks Block Public Access enabled"
        },
        {
            "finding_id": "iam_user_no_mfa",
            "resource_arn": "arn:aws:iam::123456789012:user/legacy-svc",
            "severity": "HIGH",
            "title": "IAM user has console access without MFA"
        }
    ]


# --- MAIN CLI LOGIC (ARGPARSE) ---
def main():
    """
    (dev) CLI entry point. Parses CLI options, runs CSPM finding triage, handles file exports,
    and manages CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="CSPM-Prowler-Triager: Ingests and triages Prowler CSPM scan reports."
    )
    
    parser.add_argument('action', choices=['triage'], help="Action to execute (currently 'triage')")
    parser.add_argument('--report', type=str, help="Path to Prowler JSON report file", default=None)
    parser.add_argument('--output', type=str, help="File path to save triage JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run triager using simulated mock Prowler findings")
    
    args = parser.parse_args()

    if args.action == 'triage':
        findings = []

        if args.mock:
            print("[*] MOCK mode active. Loading simulated Prowler findings dataset...")
            findings = get_mock_prowler_findings()
        elif args.report:
            report_path = Path(args.report)
            if not report_path.exists():
                print(f"[!] Error: Report file not found at {report_path}", file=sys.stderr)
                sys.exit(1)
            try:
                findings = json.loads(report_path.read_text(encoding='utf-8'))
            except Exception as e:
                print(f"[!] Error parsing JSON report: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print("[!] Error: You must specify either --report <path> or --mock", file=sys.stderr)
            sys.exit(1)

        triager = CSPMTriager()
        report, failure_count = triager.process_findings(findings)

        json_output = json.dumps(report, indent=4)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Triage results successfully written to: {output_path.absolute()}")
        else:
            print(json_output)

        # --- PIPELINE EXIT CODE HANDLING ---
        if failure_count > 0:
            print(f"\n[!] SECURITY ALERT: Detected {failure_count} actionable unmitigated CRITICAL/HIGH finding(s) requiring remediation!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on actionable CSPM failures
        else:
            print("\n[+] SUCCESS: CSPM posture triage completed with zero unmitigated high-risk findings.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()