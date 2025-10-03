import dns.resolver
import dns.query
import dns.zone
import socket
import argparse
import concurrent.futures
import ipaddress
import sys
import json
import os
from typing import List, Dict, Any

class DNSReconTool:
    def __init__(self, domain: str, wordlist: List[str] = None):
        self.domain = domain
        self.wordlist = wordlist or self._default_wordlist()
        self.results = {
            'subdomains': [],
            'dns_records': {}
        }

    def _default_wordlist(self) -> List[str]:
        return [
            'www', 'mail', 'admin', 'blog', 'dev', 'test', 'staging', 
            'api', 'cdn', 'app', 'portal', 'vpn', 'ns1', 'ns2', 
            'smtp', 'ftp', 'ssh', 'remote', 'support', 'help'
        ]

    def resolve_subdomain(self, subdomain: str) -> Dict[str, Any]:
        try:
            full_domain = f"{subdomain}.{self.domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            
            record_details = {
                'domain': full_domain,
                'ips': [str(rdata) for rdata in answers],
                'status': 'active'
            }
            
            return record_details
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception as e:
            return {'error': str(e)}

    def scan_subdomains(self, max_workers: int = 20) -> List[Dict[str, Any]]:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.resolve_subdomain, sub): sub for sub in self.wordlist}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result.get('status') == 'active':
                    self.results['subdomains'].append(result)
        
        return self.results['subdomains']

    def get_dns_records(self) -> Dict[str, List[str]]:
        record_types = ['A', 'MX', 'TXT', 'CNAME', 'NS']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.results['dns_records'][record_type] = [str(rdata) for rdata in answers]
            except Exception:
                self.results['dns_records'][record_type] = []
        
        return self.results['dns_records']

    def analyze_dns_security(self) -> Dict[str, Any]:
        security_report = {
            'dns_amplification_risk': False,
            'open_resolvers': [],
            'potential_vulnerabilities': []
        }

        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                ns_ip = socket.gethostbyname(str(ns))
                
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameserver = [ns_ip]
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    
                    test_query = resolver.resolve('google.com', 'A')
                    
                    if len(test_query) > 10:
                        security_report['dns_amplification_risk'] = True
                        security_report['open_resolvers'].append(ns_ip)
                
                except Exception:
                    pass
        
        except Exception:
            pass
        
        return security_report

def main():
    parser = argparse.ArgumentParser(description='DNS Reconnaissance and Analysis Tool')
    parser.add_argument('domain', help='Domain to analyze')
    parser.add_argument('-s', '--subdomains', action='store_true', help='Perform subdomain enumeration')
    parser.add_argument('-r', '--records', action='store_true', help='Retrieve DNS records')
    parser.add_argument('-a', '--analyze', action='store_true', help='Perform DNS security analysis')
    
    args = parser.parse_args()
    
    dns_tool = DNSReconTool(args.domain)
    
    if args.subdomains:
        print("Scanning Subdomains:")
        subdomains = dns_tool.scan_subdomains()
        for subdomain in subdomains:
            print(f"Found: {subdomain['domain']} - IPs: {subdomain['ips']}")
    
    if args.records:
        print("\nDNS Records:")
        records = dns_tool.get_dns_records()
        print(json.dumps(records, indent=2))
    
    if args.analyze:
        print("\nDNS Security Analysis:")
        security_report = dns_tool.analyze_dns_security()
        print(json.dumps(security_report, indent=2))

if __name__ == '__main__':
    main()