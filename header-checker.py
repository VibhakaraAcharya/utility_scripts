import requests
from datetime import datetime
import csv
import sys
from urllib.parse import urlparse

class HeaderChecker:
    def __init__(self):
        self.security_headers = {
            'Strict-Transport-Security': 'Missing HSTS',
            'Content-Security-Policy': 'Missing CSP',
            'X-Frame-Options': 'Missing Clickjacking Protection',
            'X-Content-Type-Options': 'Missing MIME-type Protection',
            'X-XSS-Protection': 'Missing XSS Protection',
            'Referrer-Policy': 'Missing Referrer Policy',
            'Permissions-Policy': 'Missing Permissions Policy',
            'Cache-Control': 'Missing Cache Control',
            'Content-Encoding': 'Compression Status',
            'Server': 'Server Information Disclosure'
        }

    def check_headers(self, url):
        if not url.startswith('http'):
            url = 'https://' + url
        
        try:
            response = requests.get(url, verify=True, allow_redirects=True)
            headers = response.headers
            
            results = {
                'url': url,
                'status_code': response.status_code,
                'all_headers': dict(headers),
                'security_analysis': {},
                'compression': 'gzip' in headers.get('Content-Encoding', '').lower(),
                'server_info': headers.get('Server', 'Not Disclosed'),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Analyze security headers
            for header, description in self.security_headers.items():
                present = header in headers
                value = headers.get(header, 'Not Set')
                results['security_analysis'][header] = {
                    'present': present,
                    'value': value,
                    'description': description
                }
            
            return results
            
        except requests.exceptions.SSLError as e:
            return {'error': f'SSL Error: {str(e)}'}
        except requests.exceptions.RequestException as e:
            return {'error': f'Request Error: {str(e)}'}

def save_to_csv(results, filename):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Write headers
        writer.writerow(['URL', 'Header Name', 'Value', 'Status', 'Description'])
        
        # Write results
        for url, result in results.items():
            if 'error' in result:
                writer.writerow([url, 'ERROR', result['error'], 'ERROR', 'Error occurred'])
                continue
                
            # Write all headers
            for header, value in result['all_headers'].items():
                writer.writerow([url, header, value, 'Present', 'Raw Header'])
            
            # Write security analysis
            for header, details in result['security_analysis'].items():
                status = 'Present' if details['present'] else 'Missing'
                writer.writerow([
                    url,
                    header,
                    details['value'],
                    status,
                    details['description']
                ])

def main():
    if len(sys.argv) < 2:
        print("Usage: python header_checker.py domain1.com domain2.com ...")
        sys.exit(1)

    checker = HeaderChecker()
    results = {}
    
    print("\nChecking headers for specified domains...")
    for domain in sys.argv[1:]:
        print(f"\nAnalyzing {domain}:")
        result = checker.check_headers(domain)
        results[domain] = result
        
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
            continue
            
        print(f"Status Code: {result['status_code']}")
        print("\nHeaders found:")
        for header, value in result['all_headers'].items():
            print(f"{header}: {value}")
            
        print("\nSecurity Analysis:")
        for header, details in result['security_analysis'].items():
            status = '✅' if details['present'] else '❌'
            print(f"{status} {header}: {details['value']}")
        
        if result['compression']:
            print("\n⚠️ WARNING: GZIP compression is enabled (potential BREACH vulnerability)")

    # Save results
    output_file = f'header_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    save_to_csv(results, output_file)
    print(f"\nDetailed results saved to {output_file}")

if __name__ == "__main__":
    main()
