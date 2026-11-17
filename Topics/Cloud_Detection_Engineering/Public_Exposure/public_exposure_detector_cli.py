# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting audit reports.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.
import boto3     # (dev) Official AWS SDK for Python to query CloudTrail.
from botocore.exceptions import ClientError
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.


class PublicExposureDetector:
    """
    (dev) Public Exposure Detector class. Parses CloudTrail event telemetry to catch
    the exact moment S3 buckets or EC2 Security Groups become publicly accessible.
    """

    S3_EXPOSURE_EVENTS = {"PutBucketAcl", "PutBucketPolicy", "PutPublicAccessBlock"}
    SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017, 6379}

    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes AWS session and CloudTrail client.

        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.ct = session.client('cloudtrail', region_name='us-east-1')

    def _inspect_s3_event(self, event_name, actor, event_time, req_params):
        """
        (dev) Evaluates S3 mutation parameters for public exposure vectors.
        """
        bucket_name = req_params.get('bucketName', 'UnknownBucket')
        params_serialized = json.dumps(req_params)

        if event_name == "PutBucketAcl":
            acl = req_params.get('x-amz-acl', '')
            if acl in ("public-read", "public-read-write", "authenticated-read") or "AllUsers" in params_serialized:
                return {
                    "resource_type": "S3 Bucket",
                    "resource_name": bucket_name,
                    "actor": actor,
                    "event_name": event_name,
                    "mitre_id": "T1530",
                    "severity": "CRITICAL",
                    "status": "FAIL",
                    "detail": (
                        f"PUBLIC S3 ACL: Principal '{actor}' applied public ACL ('{acl or 'AllUsers'}') "
                        f"to bucket '{bucket_name}' at {event_time}."
                    )
                }

        elif event_name == "PutBucketPolicy":
            policy_raw = req_params.get('bucketPolicy', {})
            policy_str = json.dumps(policy_raw) if isinstance(policy_raw, dict) else str(policy_raw)
            if ('"Principal":"*"' in policy_str.replace(" ", "") or '"AWS":"*"' in policy_str.replace(" ", "")) and "Condition" not in policy_str:
                return {
                    "resource_type": "S3 Bucket",
                    "resource_name": bucket_name,
                    "actor": actor,
                    "event_name": event_name,
                    "mitre_id": "T1530",
                    "severity": "CRITICAL",
                    "status": "FAIL",
                    "detail": (
                        f"PUBLIC S3 POLICY: Principal '{actor}' attached an unconditional wildcard ('*') "
                        f"bucket policy to '{bucket_name}' at {event_time}."
                    )
                }

        elif event_name == "PutPublicAccessBlock":
            bpa_cfg = req_params.get('PublicAccessBlockConfiguration', {})
            disabled_flags = [
                flag for flag in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets"
                )
                if bpa_cfg.get(flag) is False
            ]
            if disabled_flags:
                return {
                    "resource_type": "S3 Bucket",
                    "resource_name": bucket_name,
                    "actor": actor,
                    "event_name": event_name,
                    "mitre_id": "T1562.001",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "detail": (
                        f"S3 BPA DISABLED: Principal '{actor}' disabled Block Public Access flags "
                        f"({', '.join(disabled_flags)}) on bucket '{bucket_name}' at {event_time}."
                    )
                }

        return None

    def _inspect_sg_event(self, actor, event_time, req_params):
        """
        (dev) Evaluates AuthorizeSecurityGroupIngress parameters for 0.0.0.0/0 or ::/0 exposure.
        """
        sg_id = req_params.get('groupId', req_params.get('groupName', 'UnknownSG'))
        ip_permissions = req_params.get('ipPermissions', {}).get('items', [])
        params_str = json.dumps(req_params)

        if "0.0.0.0/0" not in params_str and "::/0" not in params_str:
            return None

        exposed_sensitive = []
        exposed_ports = []

        for perm in ip_permissions:
            from_port = perm.get('fromPort', 0)
            to_port = perm.get('toPort', 65535)
            ip_ranges = perm.get('ipRanges', {}).get('items', [])
            ipv6_ranges = perm.get('ipv6Ranges', {}).get('items', [])

            is_world_open = any(r.get('cidrIp') == '0.0.0.0/0' for r in ip_ranges) or any(
                r.get('cidrIpv6') == '::/0' for r in ipv6_ranges
            )

            if is_world_open:
                port_label = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                exposed_ports.append(port_label)
                for s_port in self.SENSITIVE_PORTS:
                    if from_port <= s_port <= to_port:
                        exposed_sensitive.append(s_port)

        if exposed_sensitive:
            return {
                "resource_type": "EC2 Security Group",
                "resource_name": sg_id,
                "actor": actor,
                "event_name": "AuthorizeSecurityGroupIngress",
                "mitre_id": "T1190",
                "severity": "CRITICAL",
                "status": "FAIL",
                "detail": (
                    f"CRITICAL SG EXPOSURE: Principal '{actor}' opened sensitive administrative/DB port(s) "
                    f"{sorted(set(exposed_sensitive))} to the internet (0.0.0.0/0) on '{sg_id}' at {event_time}."
                )
            }

        return {
            "resource_type": "EC2 Security Group",
            "resource_name": sg_id,
            "actor": actor,
            "event_name": "AuthorizeSecurityGroupIngress",
            "mitre_id": "T1190",
            "severity": "HIGH",
            "status": "FAIL",
            "detail": (
                f"OPEN SG INGRESS: Principal '{actor}' added 0.0.0.0/0 ingress rule "
                f"(ports: {', '.join(exposed_ports) or 'unspecified'}) on '{sg_id}' at {event_time}."
            )
        }

    def analyze_events(self, events_list):
        """
        (dev) Iterates through CloudTrail events and detects S3 and Security Group exposure mutations.

        Returns:
        - tuple (findings, risk_count): List of findings and count of detected exposures.
        """
        findings = []
        risk_count = 0

        for event in events_list:
            event_name = event.get('EventName')
            actor = event.get('Username', 'UnknownPrincipal')
            event_time = str(event.get('EventTime', 'UnknownTime'))
            raw_detail = event.get('CloudTrailEvent', '{}')

            try:
                detail = json.loads(raw_detail) if isinstance(raw_detail, str) else raw_detail
            except json.JSONDecodeError:
                detail = {}

            req_params = detail.get('requestParameters', {}) or {}
            finding = None

            if event_name in self.S3_EXPOSURE_EVENTS:
                finding = self._inspect_s3_event(event_name, actor, event_time, req_params)
            elif event_name == "AuthorizeSecurityGroupIngress":
                finding = self._inspect_sg_event(actor, event_time, req_params)

            if finding:
                risk_count += 1
                findings.append(finding)

        if not findings:
            findings.append({
                "resource_type": "Cloud Exposure Monitor",
                "resource_name": "S3 & Security Groups",
                "actor": "N/A",
                "event_name": "None",
                "mitre_id": "T1530 / T1190",
                "severity": "INFO",
                "status": "PASS",
                "detail": "No public S3 exposure or 0.0.0.0/0 Security Group ingress events detected."
            })

        return findings, risk_count

    def audit_trail(self):
        """
        (dev) Fetches live CloudTrail events via LookupEvents API and evaluates exposure mutations.
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
                "mitre_id": "N/A",
                "severity": "ERROR",
                "status": "ERROR",
                "detail": str(ce)
            }], 1


# --- MOCK DATA GENERATOR ---
def get_mock_exposure_events():
    """
    (dev) Simulates real-world accidental and malicious public exposure events:
    1. PutPublicAccessBlock disabling protection on a sensitive bucket.
    2. PutBucketPolicy granting unconditional Principal '*' read access.
    3. AuthorizeSecurityGroupIngress opening SSH (port 22) to 0.0.0.0/0.
    """
    return [
        {
            "EventName": "PutPublicAccessBlock",
            "Username": "ci-deploy-bot",
            "EventTime": "2026-11-17T18:10:00Z",
            "CloudTrailEvent": json.dumps({
                "requestParameters": {
                    "bucketName": "fintech-kyc-documents-prod",
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": True
                    }
                }
            })
        },
        {
            "EventName": "PutBucketPolicy",
            "Username": "ci-deploy-bot",
            "EventTime": "2026-11-17T18:10:45Z",
            "CloudTrailEvent": json.dumps({
                "requestParameters": {
                    "bucketName": "fintech-kyc-documents-prod",
                    "bucketPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::fintech-kyc-documents-prod/*"
                        }]
                    }
                }
            })
        },
        {
            "EventName": "AuthorizeSecurityGroupIngress",
            "Username": "contractor-dev",
            "EventTime": "2026-11-17T18:22:15Z",
            "CloudTrailEvent": json.dumps({
                "requestParameters": {
                    "groupId": "sg-0912837465abcdef0",
                    "ipPermissions": {
                        "items": [{
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {
                                "items": [{"cidrIp": "0.0.0.0/0"}]
                            }
                        }]
                    }
                }
            })
        }
    ]


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate CloudTrail locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses CLI options, executes public exposure detection,
    exports JSON reports, and sets CI/CD pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="Public-Exposure-Detector: Detects real-time S3 and Security Group public exposure events."
    )

    parser.add_argument('action', choices=['audit'], help="Action to execute ('audit')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report", default=None)
    parser.add_argument('--mock', action='store_true', help="Run detector using simulated exposure events")

    args = parser.parse_args()

    if args.action == 'audit':
        detector = PublicExposureDetector(profile=args.profile)

        if args.mock:
            print("[*] MOCK mode active. Analyzing simulated S3 and Security Group exposure events...")
            findings, risk_count = detector.analyze_events(get_mock_exposure_events())
        else:
            findings, risk_count = detector.audit_trail()

        report = {
            "metadata": {
                "philosophy": (
                    "Public Exposure Detection: Minimize the exposure window by catching S3 public "
                    "policy/ACL/BPA mutations and 0.0.0.0/0 Security Group ingress changes immediately in CloudTrail."
                ),
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
                f"\n[!] SECURITY ALERT: Detected {risk_count} public exposure event(s) requiring immediate remediation!",
                file=sys.stderr
            )
            sys.exit(1)
        else:
            print("\n[+] SUCCESS: No public exposure mutations detected in CloudTrail.", file=sys.stderr)
            sys.exit(0)


if __name__ == "__main__":
    main()