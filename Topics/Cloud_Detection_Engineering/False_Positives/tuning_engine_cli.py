# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting tuning audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.


class DetectionTuningEngine:
    """
    (dev) Detection Tuning & False Positive Governance Engine.
    Evaluates raw security events against documented tuning rules (allowlists + condition narrowing)
    to eliminate alert fatigue without introducing false negatives.
    """

    def __init__(self, tuning_rules):
        """
        (dev) Initializes the engine with a list of documented tuning rule dictionaries.
        Validates that every tuning rule carries mandatory governance documentation.
        """
        self.tuning_rules = self._validate_tuning_governance(tuning_rules)

    def _validate_tuning_governance(self, rules):
        """
        (dev) Enforces Detection Engineering governance: no undocumented exceptions allowed.
        Every rule must specify 'rule_id', 'event_name', 'rationale', and 'approved_by'.
        """
        validated = []
        required_keys = {"rule_id", "event_name", "rationale", "approved_by"}
        for rule in rules:
            missing = required_keys - set(rule.keys())
            if missing:
                raise ValueError(
                    f"Undocumented tuning exception rejected! Missing keys {sorted(missing)} in rule: {rule}"
                )
            validated.append(rule)
        return validated

    def _match_tuning_rule(self, event):
        """
        (dev) Checks if an event satisfies a documented false-positive tuning condition.
        Returns the matching tuning rule dict or None if the event is an actionable threat.
        """
        event_name = event.get("EventName")
        principal = event.get("PrincipalArn", "")
        policy_arn = event.get("PolicyArn", "")

        for rule in self.tuning_rules:
            if rule["event_name"] != event_name:
                continue

            # Strategy 1: Whitelist known, authorized automation principal ARN
            allowed_principal = rule.get("allowed_principal")
            if allowed_principal and principal == allowed_principal:
                return rule

            # Strategy 2: Condition narrowing (e.g., ignore benign ReadOnly policy attachments)
            benign_policy_substring = rule.get("ignore_policy_contains")
            if benign_policy_substring and benign_policy_substring in policy_arn:
                return rule

        return None

    def evaluate_events(self, events):
        """
        (dev) Separates raw CloudTrail events into suppressed false positives (with audit trail)
        and actionable true positive security alerts.
        """
        actionable_findings = []
        suppressed_findings = []

        for event in events:
            event_name = event.get("EventName", "UnknownEvent")
            principal = event.get("PrincipalArn", "UnknownPrincipal")
            event_time = event.get("EventTime", "UnknownTime")
            matched_rule = self._match_tuning_rule(event)

            if matched_rule:
                suppressed_findings.append({
                    "event_name": event_name,
                    "principal": principal,
                    "event_time": event_time,
                    "status": "SUPPRESSED_FP",
                    "tuning_rule_id": matched_rule["rule_id"],
                    "rationale": matched_rule["rationale"],
                    "approved_by": matched_rule["approved_by"]
                })
            else:
                actionable_findings.append({
                    "event_name": event_name,
                    "principal": principal,
                    "event_time": event_time,
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": (
                        f"ACTIONABLE ALERT: Principal '{principal}' executed '{event_name}' at {event_time}. "
                        f"Event did not match any documented false-positive tuning baseline."
                    )
                })

        total = len(events)
        suppressed_count = len(suppressed_findings)
        actionable_count = len(actionable_findings)
        noise_reduction = round((suppressed_count / total * 100), 1) if total > 0 else 0.0

        report = {
            "metadata": {
                "philosophy": (
                    "Detection Tuning & False Positive Governance: Never blindly disable noisy rules. "
                    "Narrow conditions, document every allowlist exception with business rationale, "
                    "and preserve visibility against false negatives."
                ),
                "total_events_analyzed": total,
                "suppressed_false_positives": suppressed_count,
                "actionable_alerts": actionable_count,
                "noise_reduction_percent": noise_reduction
            },
            "actionable_findings": actionable_findings,
            "suppressed_false_positives_log": suppressed_findings
        }

        return report, actionable_count


# --- MOCK DATA GENERATORS ---
def get_mock_tuning_rules():
    """
    (dev) Returns documented SOC tuning rules with explicit rationale and approval metadata.
    """
    return [
        {
            "rule_id": "TUNE-001",
            "event_name": "CreateAccessKey",
            "allowed_principal": "arn:aws:iam::123456789012:role/github-actions-rotator",
            "rationale": "Authorized CI/CD pipeline rotating short-lived service credentials on schedule.",
            "approved_by": "secops-lead@company.com"
        },
        {
            "rule_id": "TUNE-002",
            "event_name": "AttachUserPolicy",
            "ignore_policy_contains": "ReadOnlyAccess",
            "rationale": "Narrowed detection condition: attaching ReadOnlyAccess does not grant privilege escalation.",
            "approved_by": "detection-eng@company.com"
        }
    ]


def get_mock_mixed_events():
    """
    (dev) Simulates a realistic stream mixing benign CI/CD automation noise with a real attacker event.
    """
    return [
        {
            "EventName": "CreateAccessKey",
            "PrincipalArn": "arn:aws:iam::123456789012:role/github-actions-rotator",
            "EventTime": "2026-11-21T21:00:00Z"
        },
        {
            "EventName": "AttachUserPolicy",
            "PrincipalArn": "arn:aws:iam::123456789012:role/terraform-provisioning",
            "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "EventTime": "2026-11-21T21:05:00Z"
        },
        {
            "EventName": "CreateAccessKey",
            "PrincipalArn": "arn:aws:iam::123456789012:user/compromised-analyst",
            "EventTime": "2026-11-21T21:12:45Z"
        }
    ]


# --- MAIN CLI LOGIC (ARGPARSE) ---
def main():
    """
    (dev) CLI entry point. Validates tuning rule governance, filters false positives,
    exports structured reports, and enforces CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Detection-Tuning-Engine: Applies documented false-positive tuning rules to cloud telemetry."
    )

    parser.add_argument('action', choices=['evaluate'], help="Action to execute ('evaluate')")
    parser.add_argument('--allowlist', type=str, help="Path to JSON file with documented tuning rules", default=None)
    parser.add_argument('--events', type=str, help="Path to JSON file with CloudTrail events", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run engine with simulated CI/CD noise + threat events")

    args = parser.parse_args()

    if args.action == 'evaluate':
        if args.mock:
            print("[*] MOCK mode active. Evaluating mixed CI/CD automation noise and threat events...")
            tuning_rules = get_mock_tuning_rules()
            events = get_mock_mixed_events()
        else:
            if not args.allowlist or not args.events:
                print("[!] Error: Provide both --allowlist and --events paths, or use --mock.", file=sys.stderr)
                sys.exit(1)
            tuning_rules = json.loads(Path(args.allowlist).read_text(encoding='utf-8'))
            events = json.loads(Path(args.events).read_text(encoding='utf-8'))

        try:
            engine = DetectionTuningEngine(tuning_rules)
            report, actionable_count = engine.evaluate_events(events)
        except ValueError as err:
            print(f"[!] GOVERNANCE ERROR: {err}", file=sys.stderr)
            sys.exit(1)

        json_output = json.dumps(report, indent=4)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Tuned detection report written to: {output_path.absolute()}")
        else:
            print(json_output)

        # --- PIPELINE EXIT CODE HANDLING ---
        if actionable_count > 0:
            print(
                f"\n[!] ACTIONABLE THREAT ALERT: {actionable_count} un-tuned security event(s) require SOC investigation!",
                file=sys.stderr
            )
            sys.exit(1)
        else:
            print("\n[+] SUCCESS: All events matched documented benign baselines (0 actionable alerts).", file=sys.stderr)
            sys.exit(0)


if __name__ == "__main__":
    main()