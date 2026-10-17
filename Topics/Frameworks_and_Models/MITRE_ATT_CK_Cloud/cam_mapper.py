# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing command-line options.
import json      # (dev) Library for reading logs and exporting structured JSON analysis reports.
import sys       # (dev) Provides system-level functions for exit codes and error output.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation library.

class CloudAttackMapper:
    """
    (dev) MITRE ATT&CK for Cloud mapping engine. Translates cloud API events 
    into standardized adversary tactics, techniques, and severity levels.
    """
    
    # ATT&CK Cloud Mapping Database (Dictionary mapping AWS CloudTrail Event Names to ATT&CK Techniques)
    ATTACK_SIGNATURES = {
        "CreateAccessKey": {
            "tactic": "Persistence",
            "technique_id": "T1098.001",
            "technique_name": "Account Manipulation: Additional Cloud Credentials",
            "severity": "HIGH"
        },
        "StopLogging": {
            "tactic": "Defense Evasion",
            "technique_id": "T1562.008",
            "technique_name": "Impair Defenses: Disable Cloud Trail",
            "severity": "CRITICAL"
        },
        "DeleteTrail": {
            "tactic": "Defense Evasion",
            "technique_id": "T1562.008",
            "technique_name": "Impair Defenses: Delete Cloud Trail",
            "severity": "CRITICAL"
        },
        "AttachUserPolicy": {
            "tactic": "Privilege Escalation",
            "technique_id": "T1098",
            "technique_name": "Account Manipulation: Permission Escalation",
            "severity": "HIGH"
        },
        "ListBuckets": {
            "tactic": "Discovery",
            "technique_id": "T1580",
            "technique_name": "Cloud Infrastructure Discovery",
            "severity": "LOW"
        },
        "DescribeInstances": {
            "tactic": "Discovery",
            "technique_id": "T1580",
            "technique_name": "Cloud Infrastructure Discovery",
            "severity": "LOW"
        },
        "GetObject": {
            "tactic": "Collection",
            "technique_id": "T1530",
            "technique_name": "Data from Cloud Storage Object",
            "severity": "MEDIUM"
        }
    }

    def __init__(self, log_data):
        """
        (dev) Class constructor. Initializes the mapper with log records.
        
        Parameters:
        - log_data (list): List of dictionaries representing cloud log events.
        """
        self.log_data = log_data

    def map_logs_to_attack(self):
        """
        (dev) Iterates through log events, matches them against known ATT&CK signatures,
        and compiles structured findings with risk assessments.
        
        Returns:
        - tuple (report, high_risk_count): Structured report dictionary and count of critical/high findings.
        """
        mapped_findings = []
        high_risk_count = 0

        for event in self.log_data:
            event_name = event.get('eventName')
            username = event.get('userIdentity', {}).get('userName', 'unknown-user')
            
            # Check if the event matches a known MITRE ATT&CK technique signature
            if event_name in self.ATTACK_SIGNATURES:
                sig = self.ATTACK_SIGNATURES[event_name]
                
                if sig['severity'] in ['HIGH', 'CRITICAL']:
                    high_risk_count += 1

                mapped_findings.append({
                    "event_name": event_name,
                    "username": username,
                    "tactic": sig['tactic'],
                    "technique_id": sig['technique_id'],
                    "technique_name": sig['technique_name'],
                    "severity": sig['severity']
                })

        # Compile final analysis report dictionary
        report = {
            "metadata": {
                "philosophy": "Cloud ATT&CK Mapper: Translating cloud telemetry into actionable threat intelligence.",
                "total_events_analyzed": len(self.log_data),
                "matched_techniques_count": len(mapped_findings)
            },
            "mapped_findings": mapped_findings
        }
        
        return report, high_risk_count


# --- HELPER FUNCTION FOR SAMPLE LOG GENERATION ---
def generate_sample_logs():
    """
    (dev) Generates a sample synthetic CloudTrail log file containing both 
    benign discovery actions and malicious adversary techniques (Persistence, Defense Evasion).
    """
    sample_events = [
        {
            "eventName": "ListBuckets",
            "userIdentity": {"userName": "developer-john"}
        },
        {
            "eventName": "CreateAccessKey",
            "userIdentity": {"userName": "compromised-service-account"}
        },
        {
            "eventName": "StopLogging",
            "userIdentity": {"userName": "malicious-actor"}
        },
        {
            "eventName": "DescribeInstances",
            "userIdentity": {"userName": "auditor-bot"}
        }
    ]
    
    sample_path = Path("sample_cloudtrail.json")
    sample_path.write_text(json.dumps(sample_events, indent=4), encoding='utf-8')
    print(f"[*] Generated synthetic sample log file at: {sample_path.absolute()}")
    return sample_events


# --- MAIN CLI LOGIC (ARGPARSE) ---
def main():
    """
    (dev) CLI entry point. Parses command-line parameters, loads log files,
    executes MITRE ATT&CK mapping, handles report output, and manages pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="CAM-Mapper: Maps cloud audit logs against the MITRE ATT&CK for Cloud Matrix."
    )
    
    # CLI Argument definitions:
    parser.add_argument('action', choices=['analyze'], help="Action to execute (currently 'analyze')")
    parser.add_argument('--input', type=str, help="Path to input JSON log file (e.g., logs.json)", default=None)
    parser.add_argument('--sample', action='store_true', help="Generate and analyze a built-in synthetic malicious log file")
    parser.add_argument('--output', type=str, help="File path to save JSON analysis report", default=None)
    
    args = parser.parse_args()

    if args.action == 'analyze':
        log_records = []

        # Load logs from sample generator or user-provided file path
        if args.sample:
            log_records = generate_sample_logs()
        elif args.input:
            input_path = Path(args.input)
            if not input_path.exists():
                print(f"[!] ERROR: Input log file not found: {input_path.absolute()}", file=sys.stderr)
                sys.exit(1)
            log_records = json.loads(input_path.read_text(encoding='utf-8'))
        else:
            print("[!] ERROR: You must specify either --input <file> or --sample flag.", file=sys.stderr)
            sys.exit(1)

        # Initialize mapper and run analysis
        mapper = CloudAttackMapper(log_records)
        report, high_risk_count = mapper.map_logs_to_attack()

        # Convert report dictionary to formatted JSON string
        json_output = json.dumps(report, indent=4)

        # Handle file export using pathlib if output path is provided
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Analysis report successfully written to: {output_path.absolute()}")
        else:
            # Print JSON to stdout for piping (e.g., to jq)
            print(json_output)

        # --- PIPELINE EXIT CODE HANDLING ---
        if high_risk_count > 0:
            print(f"\n[!] SECURITY ALERT: Detected {high_risk_count} high-risk/critical MITRE ATT&CK techniques!", file=sys.stderr)
            sys.exit(1)  # Break pipeline on malicious technique detection
        else:
            print("\n[+] SUCCESS: No high-risk MITRE ATT&CK techniques found in logs.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()