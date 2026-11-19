# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.

try:
    import yaml  # (dev) PyYAML library for parsing Sigma YAML rule definitions.
except ImportError:
    print("[!] Missing dependency: 'pyyaml'. Install it via: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


class SigmaCloudEvaluator:
    """
    (dev) Sigma Rule Validator, Transpiler, and CloudTrail Event Evaluator.
    Enforces Detection-as-Code quality gates and executes Sigma selection logic against JSON logs.
    """

    REQUIRED_FIELDS = {"title", "id", "logsource", "detection", "level"}

    def validate_rule_schema(self, rule_data):
        """
        (dev) Validates that a Sigma rule contains all mandatory fields and MITRE ATT&CK tags.

        Returns:
        - list of validation error strings (empty if valid).
        """
        errors = []
        missing = self.REQUIRED_FIELDS - set(rule_data.keys())
        if missing:
            errors.append(f"Missing required Sigma fields: {', '.join(sorted(missing))}")

        detection = rule_data.get("detection", {})
        if not isinstance(detection, dict) or "condition" not in detection:
            errors.append("Invalid 'detection' block: missing 'condition' key.")

        tags = rule_data.get("tags", [])
        has_attack_tag = any(str(t).startswith("attack.") for t in tags)
        if not has_attack_tag:
            errors.append("Quality Gate Warning: Rule lacks MITRE ATT&CK tags (e.g., 'attack.t1562.008').")

        return errors

    def transpile_queries(self, rule_data):
        """
        (dev) Translates basic Sigma selection criteria into AWS CloudWatch Logs Insights
        and Splunk SPL queries for multi-backend portability.
        """
        detection = rule_data.get("detection", {})
        selection = detection.get("selection", {})

        cw_filters = []
        splunk_filters = []

        for field, expected in selection.items():
            if isinstance(expected, list):
                cw_list = ", ".join(f"'{v}'" for v in expected)
                cw_filters.append(f"{field} in [{cw_list}]")

                sp_or = " OR ".join(f'{field}="{v}"' for v in expected)
                splunk_filters.append(f"({sp_or})")
            else:
                cw_filters.append(f"{field} = '{expected}'")
                splunk_filters.append(f'{field}="{expected}"')

        cw_where = " and ".join(cw_filters) if cw_filters else "eventName like /.*/"
        sp_where = " AND ".join(splunk_filters) if splunk_filters else "*"

        return {
            "cloudwatch_logs_insights": (
                f"fields @timestamp, eventName, userIdentity.arn, sourceIPAddress | filter {cw_where}"
            ),
            "splunk_spl": f"index=aws_cloudtrail {sp_where}"
        }

    def evaluate_events(self, rule_data, events):
        """
        (dev) Evaluates a list of CloudTrail event dictionaries against the Sigma 'selection' block.

        Returns:
        - list of matched event dictionaries.
        """
        detection = rule_data.get("detection", {})
        selection = detection.get("selection", {})
        matches = []

        for event in events:
            is_match = True
            for field, expected in selection.items():
                actual_val = event.get(field)
                if isinstance(expected, list):
                    if actual_val not in expected:
                        is_match = False
                        break
                else:
                    if actual_val != expected:
                        is_match = False
                        break

            if is_match:
                matches.append(event)

        return matches


# --- MOCK DATA GENERATORS ---
def get_mock_sigma_rule():
    """
    (dev) Returns an in-memory Sigma rule targeting CloudTrail tampering (MITRE T1562.008).
    """
    sample_yaml = """
title: AWS CloudTrail Logging Disabled or Deleted
id: 8f9e2b10-4c7a-49d1-b8e2-7a1c9f04d211
status: stable
description: Detects StopLogging or DeleteTrail API calls indicating defense evasion.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName:
      - StopLogging
      - DeleteTrail
  condition: selection
level: critical
tags:
  - attack.defense_evasion
  - attack.t1562.008
"""
    return yaml.safe_load(sample_yaml)


def get_mock_cloudtrail_events():
    """
    (dev) Simulates CloudTrail JSON log entries (both benign and matching Sigma selection).
    """
    return [
        {
            "eventTime": "2026-11-19T19:10:00Z",
            "eventName": "DescribeInstances",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/readonly-audit"},
            "sourceIPAddress": "10.0.1.15"
        },
        {
            "eventTime": "2026-11-19T19:14:22Z",
            "eventName": "StopLogging",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/compromised-admin"},
            "sourceIPAddress": "185.220.101.45"
        }
    ]


# --- MAIN CLI LOGIC (ARGPARSE) ---
def main():
    """
    (dev) CLI entry point. Validates Sigma rule schemas, transpiles queries, evaluates logs,
    and returns CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Sigma-Cloud-Evaluator: Validates Sigma rules, transpiles queries, and tests CloudTrail logs."
    )

    parser.add_argument('action', choices=['evaluate'], help="Action to execute ('evaluate')")
    parser.add_argument('--rule', type=str, help="Path to Sigma YAML rule file", default=None)
    parser.add_argument('--events', type=str, help="Optional path to JSON file containing CloudTrail events", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON evaluation report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run evaluator with embedded Sigma rule and mock CloudTrail logs")

    args = parser.parse_args()

    if args.action == 'evaluate':
        evaluator = SigmaCloudEvaluator()

        if args.mock:
            print("[*] MOCK mode active. Loading built-in Sigma rule and simulated CloudTrail stream...")
            rule_data = get_mock_sigma_rule()
            events = get_mock_cloudtrail_events()
        else:
            if not args.rule:
                print("[!] Error: Provide --rule <path.yml> or use --mock.", file=sys.stderr)
                sys.exit(1)
            rule_path = Path(args.rule)
            if not rule_path.exists():
                print(f"[!] Error: Sigma rule file not found at {rule_path}", file=sys.stderr)
                sys.exit(1)
            rule_data = yaml.safe_load(rule_path.read_text(encoding='utf-8'))

            if args.events:
                events_path = Path(args.events)
                events = json.loads(events_path.read_text(encoding='utf-8'))
            else:
                events = get_mock_cloudtrail_events()

        schema_errors = evaluator.validate_rule_schema(rule_data)
        queries = evaluator.transpile_queries(rule_data)
        matched_events = evaluator.evaluate_events(rule_data, events)

        report = {
            "metadata": {
                "philosophy": (
                    "Detection-as-Code with Sigma: Write backend-agnostic YAML detection logic once, "
                    "enforce MITRE ATT&CK metadata, and transpile across cloud log backends."
                ),
                "rule_title": rule_data.get("title", "Untitled Rule"),
                "rule_id": rule_data.get("id", "N/A"),
                "severity": rule_data.get("level", "unknown"),
                "tags": rule_data.get("tags", []),
                "schema_valid": len(schema_errors) == 0,
                "matched_events_count": len(matched_events)
            },
            "schema_validation_errors": schema_errors,
            "transpiled_queries": queries,
            "matched_events": matched_events
        }

        json_output = json.dumps(report, indent=4)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Evaluation report saved to: {output_path.absolute()}")
        else:
            print(json_output)

        # --- PIPELINE EXIT CODE HANDLING ---
        if schema_errors:
            print(f"\n[!] SCHEMA ERROR: Sigma rule failed quality gate ({len(schema_errors)} issue(s)).", file=sys.stderr)
            sys.exit(1)

        if matched_events:
            print(
                f"\n[!] DETECTION TRIGGERED: Sigma rule '{rule_data.get('title')}' matched {len(matched_events)} event(s)!",
                file=sys.stderr
            )
            sys.exit(1)

        print("\n[+] SUCCESS: Sigma rule validated cleanly with zero threat detections.", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()