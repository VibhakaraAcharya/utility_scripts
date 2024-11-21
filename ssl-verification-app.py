import ssl
import socket
import concurrent.futures
from dataclasses import dataclass
from typing import List, Dict, Optional
import csv
from datetime import datetime
import argparse
import sys
from tqdm import tqdm

@dataclass
class SSLResult:
    hostname: str
    port: int
    protocol_versions: List[str]
    cipher_suites: List[str]
    has_cbc_ciphers: bool
    certificate_expiry: str
    vulnerabilities: List[str]
    errors: List[str]

class SSLVerifier:
    def __init__(self):
        self.supported_protocols = [
            ssl.PROTOCOL_TLSv1_2,
            ssl.PROTOCOL_TLSv1_1,
            ssl.PROTOCOL_TLSv1
        ]
        
    def check_cipher_suites(self, hostname: str, port: int) -> List[str]:
        ciphers = []
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ciphers.append(ssock.cipher())
        except Exception as e:
            return [f"Error checking ciphers: {str(e)}"]
        return ciphers

    def has_cbc_ciphers(self, ciphers: List[str]) -> bool:
        return any('CBC' in cipher[0] for cipher in ciphers if isinstance(cipher, tuple))

    def check_certificate(self, hostname: str, port: int) -> Optional[str]:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return cert['notAfter']
        except Exception as e:
            return f"Error checking certificate: {str(e)}"
        return None

    def check_vulnerabilities(self, hostname: str, port: int, ciphers: List[str]) -> List[str]:
        vulnerabilities = []
        
        if self.has_cbc_ciphers(ciphers):
            vulnerabilities.append("LUCKY13 (CBC ciphers present)")
            
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock) as ssock:
                    vulnerabilities.append("POODLE (SSLv3 enabled)")
        except:
            pass
            
        return vulnerabilities

    def verify_endpoint(self, hostname: str, port: int = 443) -> SSLResult:
        protocols = []
        ciphers = []
        vulnerabilities = []
        errors = []
        cert_expiry = None

        try:
            # Check supported protocols
            for protocol in self.supported_protocols:
                try:
                    context = ssl.SSLContext(protocol)
                    with socket.create_connection((hostname, port), timeout=10) as sock:
                        with context.wrap_socket(sock) as ssock:
                            protocols.append(ssock.version())
                except:
                    continue

            ciphers = self.check_cipher_suites(hostname, port)
            cert_expiry = self.check_certificate(hostname, port)
            vulnerabilities = self.check_vulnerabilities(hostname, port, ciphers)

        except Exception as e:
            errors.append(f"Error during verification: {str(e)}")

        return SSLResult(
            hostname=hostname,
            port=port,
            protocol_versions=protocols,
            cipher_suites=ciphers,
            has_cbc_ciphers=self.has_cbc_ciphers(ciphers),
            certificate_expiry=cert_expiry,
            vulnerabilities=vulnerabilities,
            errors=errors
        )

def save_results_to_csv(results: List[SSLResult], filename: str):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Hostname', 'Port', 'Protocols', 'Ciphers', 'CBC Ciphers', 
                        'Certificate Expiry', 'Vulnerabilities', 'Errors'])
        
        for result in results:
            writer.writerow([
                result.hostname,
                result.port,
                ', '.join(result.protocol_versions),
                ', '.join(str(c) for c in result.cipher_suites),
                result.has_cbc_ciphers,
                result.certificate_expiry,
                ', '.join(result.vulnerabilities),
                ', '.join(result.errors)
            ])

def main():
    try:
        parser = argparse.ArgumentParser(description='SSL/TLS Configuration Verification Tool')
        parser.add_argument('-f', '--file', required=True, help='Input file containing endpoints (one per line)')
        parser.add_argument('-o', '--output', help='Output CSV file', 
                            default=f'ssl_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
        parser.add_argument('-p', '--port', type=int, default=443, help='Port number (default: 443)')
        parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
        
        args = parser.parse_args()

        # Read endpoints from file
        with open(args.file, 'r') as f:
            endpoints = [line.strip() for line in f if line.strip()]

        print(f"\nStarting SSL verification for {len(endpoints)} endpoints...")
        print(f"Using {args.threads} threads")
        print(f"Results will be saved to: {args.output}\n")

        verifier = SSLVerifier()
        results = []

        # Progress bar
        with tqdm(total=len(endpoints), desc="Scanning", unit="endpoint") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                future_to_endpoint = {
                    executor.submit(verifier.verify_endpoint, endpoint, args.port): endpoint 
                    for endpoint in endpoints
                }
                
                for future in concurrent.futures.as_completed(future_to_endpoint):
                    endpoint = future_to_endpoint[future]
                    try:
                        result = future.result()
                        results.append(result)
                        pbar.update(1)
                    except Exception as e:
                        print(f"\nError verifying {endpoint}: {str(e)}")
                        pbar.update(1)

        # Save results to CSV
        save_results_to_csv(results, args.output)
        print(f"\n✅ Scan completed successfully!")
        print(f"📊 Results saved to: {args.output}")
        print("\nExiting program...")
        sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
        print("Exiting program...")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        print("Exiting program...")
        sys.exit(1)

if __name__ == "__main__":
    main()
