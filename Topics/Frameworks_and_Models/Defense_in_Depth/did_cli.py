# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing command-line flags and arguments.
import json      # (dev) Library for formatting and exporting structured JSON reports.
import sys       # (dev) Provides system-level functions, used here for exit codes and error outputs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path handling.
import boto3     # (dev) Official AWS SDK for Python to interact with cloud services.
from moto import mock_aws  # (dev) Decorator to simulate AWS APIs locally in RAM for safe testing.

class DiDAuditorCLI:
    """
    (dev) Main Defense in Depth auditor class. Evaluates whether assets are protected 
    by multiple overlapping security layers (Account, Resource, Data).
    """
    
    def __init__(self, profile=None):
        """
        (dev) Class constructor. Initializes session and S3 client.
        
        Parameters:
        - profile (str, optional): AWS CLI profile name. Defaults to None.
        """
        # Initialize session with an optional custom profile.
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        
        # Initialize S3 client (Defense in Depth applied to storage assets).
        self.s3 = session.client('s3', region_name='eu-central-1')

    def audit_defense_in_depth(self):
        """
        (dev) Audits S3 buckets against a 3-tier Defense in Depth model:
        1. Account/Perimeter Block Public Access
        2. Bucket-level Block Public Access
        3. Server-Side Encryption (SSE-KMS)
        
        Returns:
        - tuple (report, failed_checks): Dictionary report and total number of non-compliant resources.
        """
        findings = []
        failed_checks = 0

        # Check account-level public access block (Perimeter Defense Layer)
        account_bpa_enabled = False
        try:
            # Note: account public access block requires account-level API call. 
            # In a real environment or moto, we check if account settings restrict public access.
            account_bpa = self.s3.get_public_access_block(AccountId='self')
            conf = account_bpa.get('PublicAccessBlockConfiguration', {})
            account_bpa_enabled = all([conf.get('BlockPublicAcls'), conf.get('BlockPublicPolicy')])
        except Exception:
            account_bpa_enabled = False

        # Retrieve all S3 buckets for resource and data layer inspection
        buckets = self.s3.list_buckets().get('Buckets', [])
        
        for b in buckets:
            bucket_name = b['Name']
            layers_passed = 0
            total_layers = 3  # Perimeter, Resource BPA, Data Encryption

            # Layer 1: Perimeter Defense (Account BPA)
            if account_bpa_enabled:
                layers_passed += 1

            # Layer 2: Resource Defense (Bucket-level Block Public Access)
            bucket_bpa_passed = False
            try:
                bpa_conf = self.s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                bucket_bpa_passed = all([
                    bpa_conf.get('BlockPublicAcls'), 
                    bpa_conf.get('BlockPublicPolicy'),
                    bpa_conf.get('IgnorePublicAcls'),
                    bpa_conf.get('RestrictPublicBuckets')
                ])
                if bucket_bpa_passed:
                    layers_passed += 1
            except Exception:
                bucket_bpa_passed = False

            # Layer 3: Data Defense (Server-Side Encryption / KMS)
            encryption_passed = False
            try:
                enc_conf = self.s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc_conf.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                if len(rules) > 0:
                    encryption_passed = True
                    layers_passed += 1
            except Exception:
                encryption_passed = False

            # Defense in Depth rule: Resource must pass all layers to be fully secure
            is_fully_defended = (layers_passed == total_layers)

            if not is_fully_defended:
                failed_checks += 1

            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "defense_layers_total": total_layers,
                "layers_passed": layers_passed,
                "details": {
                    "perimeter_layer_account_bpa": account_bpa_enabled,
                    "resource_layer_bucket_bpa": bucket_bpa_passed,
                    "data_layer_encryption": encryption_passed
                },
                "status": "PASS" if is_fully_defended else "FAIL"
            })

        # Compile final structured report dictionary
        report = {
            "metadata": {
                "philosophy": "Defense in Depth: Multiple independent security controls protecting the same asset.",
                "total_checks": len(findings),
                "failed_checks": failed_checks
            },
            "findings": findings
        }
        
        return report, failed_checks


# --- HELPER FUNCTION FOR MOCK DATA GENERATION (MOTO) ---
def setup_mock_environment():
    """
    (dev) Populates the in-memory Moto environment with test assets:
    - One fully defended bucket (Account BPA + Bucket BPA + Encryption)
    - One partially exposed bucket (Missing encryption and bucket BPA)
    """
    s3 = boto3.client('s3', region_name='eu-central-1')

    # Set Account-level Public Access Block (Perimeter Defense)
    s3.put_public_access_block(
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True, 
            'IgnorePublicAcls': True, 
            'BlockPublicPolicy': True, 
            'RestrictPublicBuckets': True
        }
    )

    # 1. Fully Defended Bucket (Passes all 3 layers)
    s3.create_bucket(Bucket='fully-defended-bucket', CreateBucketConfiguration={'LocationConstraint': 'eu-central-1'})
    s3.put_public_access_block(
        Bucket='fully-defended-bucket',
        PublicAccessBlockConfiguration={'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}
    )
    s3.put_bucket_encryption(
        Bucket='fully-defended-bucket',
        ServerSideEncryptionConfiguration={
            'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms'}}]
        }
    )

    # 2. Partially Exposed Bucket (Fails multiple defense layers - FAIL)
    s3.create_bucket(Bucket='partially-exposed-bucket', CreateBucketConfiguration={'LocationConstraint': 'eu-central-1'})


# --- MAIN CLI LOGIC (ARGPARSE) ---
@mock_aws  # (dev) Intercepts boto3 calls to simulate AWS locally in RAM.
def main():
    """
    (dev) CLI entry point. Parses command-line arguments, executes Defense in Depth audits,
    handles reporting outputs, and manages pipeline exit codes.
    """
    parser = argparse.ArgumentParser(
        description="DiD-Auditor: Evaluates Defense in Depth posture for AWS S3 assets."
    )
    
    # CLI Argument definitions:
    parser.add_argument('action', choices=['scan'], help="Action to execute (currently 'scan')")
    parser.add_argument('--profile', type=str, help="AWS CLI profile name to use", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON report (e.g., did_results.json)", default=None)
    parser.add_argument('--mock', action='store_true', help="Run auditor inside an isolated Moto virtual environment")
    
    args = parser.parse_args()

    if args.action == 'scan':
        # If mock flag is enabled, populate local mock infrastructure.
        if args.mock:
            print("[*] MOCK mode active. Generating virtual Defense in Depth testbed...")
            setup_mock_environment()

        # Initialize auditor instance with specified profile.
        auditor = DiDAuditorCLI(profile=args.profile)
        report, failed_checks = auditor.audit_defense_in_depth()

        # Convert report dictionary to formatted JSON string.
        json_output = json.dumps(report, indent=4)

        # Handle file export using pathlib if output path is provided.
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Results successfully written to: {output_path.absolute()}")
        else:
            # Print JSON to stdout for piping (e.g., to jq).
            print(json_output)

        # --- PIPELINE EXIT CODE HANDLING ---
        if failed_checks > 0:
            print(f"\n[!] ERROR: Found {failed_checks} resources lacking full Defense in Depth compliance.", file=sys.stderr)
            sys.exit(1)  # Break pipeline on failure
        else:
            print("\n[+] SUCCESS: All resources meet multi-layer Defense in Depth standards.", file=sys.stderr)
            sys.exit(0)  # Pass pipeline

if __name__ == "__main__":
    main()