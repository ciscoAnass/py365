import sys
import socket
import requests
import concurrent.futures
import dns.resolver
import ssl
import json
import re
from urllib.parse import urlparse
from typing import List, Set
from datetime import datetime

class SubdomainEnumerator:
    def __init__(self, domain: str, wordlist_size: int = 1000, threads: int = 20):
        self.domain = domain
        self.threads = threads
        self.discovered_subdomains: Set[str] = set()
        self.wordlist = self._generate_wordlist(wordlist_size)

    def _generate_wordlist(self, size: int) -> List[str]:
        base_words = [
            'www', 'mail', 'admin', 'blog', 'dev', 'test', 'staging', 'api', 
            'cdn', 'app', 'portal', 'dashboard', 'support', 'login', 'backend',
            'frontend', 'web', 'server', 'proxy', 'vpn', 'remote', 'internal',
            'external', 'secure', 'private', 'public', 'cloud', 'service'
        ]
        return base_words[:size]

    def brute_force_subdomains(self) -> None:
        def check_subdomain(word: str) -> None:
            subdomain = f"{word}.{self.domain}"
            try:
                socket.gethostbyname(subdomain)
                self.discovered_subdomains.add(subdomain)
                print(f"[BRUTE] Found: {subdomain}")
            except socket.gaierror:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_subdomain, self.wordlist)

    def check_certificate_transparency(self) -> None:
        ct_url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            response = requests.get(ct_url, timeout=10)
            if response.status_code == 200:
                certs = response.json()
                for cert in certs:
                    name_value = cert.get('name_value', '')
                    subdomains = re.findall(r'([a-zA-Z0-9-]+\.' + re.escape(self.domain) + ')', name_value)
                    self.discovered_subdomains.update(subdomains)
                    for subdomain in subdomains:
                        print(f"[CT] Found: {subdomain}")
        except Exception as e:
            print(f"Certificate Transparency error: {e}")

    def check_virustotal(self) -> None:
        vt_url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': 'YOUR_VIRUSTOTAL_API_KEY', 'domain': self.domain}
        try:
            response = requests.get(vt_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                self.discovered_subdomains.update(subdomains)
                for subdomain in subdomains:
                    print(f"[VT] Found: {subdomain}")
        except Exception as e:
            print(f"VirusTotal error: {e}")

    def check_dns_records(self) -> None:
        record_types = ['A', 'CNAME', 'MX', 'NS']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                for rdata in answers:
                    if hasattr(rdata, 'target'):
                        subdomain = str(rdata.target).rstrip('.')
                        if subdomain.endswith(self.domain):
                            self.discovered_subdomains.add(subdomain)
                            print(f"[DNS] Found: {subdomain}")
            except Exception:
                pass

    def enumerate(self) -> Set[str]:
        print(f"Starting subdomain enumeration for {self.domain}")
        methods = [
            self.brute_force_subdomains,
            self.check_certificate_transparency,
            self.check_virustotal,
            self.check_dns_records
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(methods)) as executor:
            executor.map(lambda method: method(), methods)

        return self.discovered_subdomains

def main():
    if len(sys.argv) < 2:
        print("Usage: python subdomain_enum.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    enumerator = SubdomainEnumerator(domain)
    results = enumerator.enumerate()

    print("\n--- Subdomain Enumeration Results ---")
    print(f"Total Subdomains Found: {len(results)}")
    for subdomain in sorted(results):
        print(subdomain)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"subdomains_{timestamp}.txt", "w") as f:
        f.write("\n".join(sorted(results)))

if __name__ == "__main__":
    main()