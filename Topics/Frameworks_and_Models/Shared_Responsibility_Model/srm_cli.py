import argparse
import json
import sys
from pathlib import Path
import boto3
from moto import mock_aws

class SRMAuditorCLI:
    def __init__(self, profile=None):
        # Inicjalizacja sesji z konkretnym profilem (jeśli podano)
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.s3 = session.client('s3', region_name='eu-central-1')
        self.ec2 = session.client('ec2', region_name='eu-central-1')

    def scan_in_the_cloud_layer(self):
        """
        Skanuje zasoby pod kątem odpowiedzialności klienta ("in the cloud"):
        - Konfiguracja usług (S3 BPA)
        - Konfiguracja warstwy sieciowej (EC2 Security Groups)
        """
        findings = []
        failed_checks = 0

        # 1. Kontrola S3 (Dane)
        buckets = self.s3.list_buckets().get('Buckets', [])
        for b in buckets:
            name = b['Name']
            bpa_status = False
            try:
                conf = self.s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
                bpa_status = all([conf.get('BlockPublicAcls'), conf.get('BlockPublicPolicy')])
            except Exception:
                bpa_status = False

            if not bpa_status: failed_checks += 1
            
            findings.append({
                "service": "S3",
                "resource": name,
                "responsibility_layer": "Data Security (Customer)",
                "check": "Block Public Access Enabled",
                "status": "PASS" if bpa_status else "FAIL"
            })

        # 2. Kontrola EC2 (Sieć / Patching boundary)
        sgs = self.ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            sg_id = sg['GroupId']
            open_ssh = False
            for rule in sg.get('IpPermissions', []):
                if rule.get('FromPort') == 22 or rule.get('ToPort') == 22:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            open_ssh = True

            if open_ssh: failed_checks += 1

            findings.append({
                "service": "EC2",
                "resource": sg_id,
                "responsibility_layer": "Network & Firewall (Customer)",
                "check": "SSH Port 22 Not Public",
                "status": "FAIL" if open_ssh else "PASS"
            })

        # Złożenie ostatecznego raportu JSON
        report = {
            "metadata": {
                "philosophy": "Customer is responsible for security 'IN the cloud' (services configuration, IAM, data, patching).",
                "total_checks": len(findings),
                "failed_checks": failed_checks
            },
            "findings": findings
        }
        
        return report, failed_checks


# --- FUNKCJA POMOCNICZA DO GENEROWANIA DANYCH (MOTO) ---
def setup_mock_environment():
    """Generuje dziurawą i bezpieczną infrastrukturę w pamięci do testów skanera."""
    s3 = boto3.client('s3', region_name='eu-central-1')
    ec2 = boto3.client('ec2', region_name='eu-central-1')

    # Bezpieczny kubełek
    s3.create_bucket(Bucket='secure-data-bucket', CreateBucketConfiguration={'LocationConstraint': 'eu-central-1'})
    s3.put_public_access_block(Bucket='secure-data-bucket', PublicAccessBlockConfiguration={'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True})
    
    # Dziurawy kubełek (FAIL)
    s3.create_bucket(Bucket='vulnerable-leak-bucket', CreateBucketConfiguration={'LocationConstraint': 'eu-central-1'})

    # Dziurawa Security Group (FAIL)
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    sg = ec2.create_security_group(GroupName='insecure-sg', Description='SSH Open', VpcId=vpc['Vpc']['VpcId'])
    ec2.authorize_security_group_ingress(GroupId=sg['GroupId'], IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])


# --- GŁÓWNA LOGIKA CLI (ARGPARSE) ---
@mock_aws
def main():
    # 1. Konfiguracja CLI za pomocą argparse
    parser = argparse.ArgumentParser(
        description="SRM-Auditor: Skaner odpowiedzialności klienta 'In The Cloud'."
    )
    parser.add_argument('action', choices=['scan'], help="Akcja do wykonania (obecnie tylko 'scan')")
    parser.add_argument('--profile', type=str, help="Nazwa profilu AWS CLI do użycia", default=None)
    parser.add_argument('--output', type=str, help="Ścieżka do zapisu pliku JSON (np. results.json)", default=None)
    parser.add_argument('--mock', action='store_true', help="Uruchom skaner w izolowanym, wirtualnym środowisku Moto")
    
    args = parser.parse_args()

    if args.action == 'scan':
        # Jeśli użyto flagi --mock, generujemy dane w pamięci
        if args.mock:
            print("[*] Tryb MOCK aktywny. Generowanie wirtualnej infrastruktury...")
            setup_mock_environment()

        # Uruchomienie audytora
        auditor = SRMAuditorCLI(profile=args.profile)
        report, failed_checks = auditor.scan_in_the_cloud_layer()

        # Konwersja do czytelnego JSON
        json_output = json.dumps(report, indent=4)

        # Logika zapisu za pomocą pathlib
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True) # Tworzy foldery jeśli nie istnieją
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Wyniki zapisano do pliku: {output_path.absolute()}")
        else:
            # Wypisanie na standardowe wyjście (stdout), by umożliwić pipe'owanie (np. do 'jq')
            print(json_output)

        # --- OBSŁUGA KODÓW WYJŚCIA (Exit Codes) ---
        if failed_checks > 0:
            print(f"\n[!] BŁĄD: Wykryto {failed_checks} naruszeń w warstwie odpowiedzialności klienta (IN the cloud).", file=sys.stderr)
            sys.exit(1) # Pipeline Breaking
        else:
            print("\n[+] SUKCES: Konfiguracja 'IN the cloud' zgodna ze sztuką.", file=sys.stderr)
            sys.exit(0)

if __name__ == "__main__":
    main()