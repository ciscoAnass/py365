import os
import sys
import re
import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# 3rd party libraries: requests, beautifulsoup4

def google_dork(domain):
    """
    Perform Google dorks to find subdomains.
    """
    subdomains = set()
    query = f'site:{domain} -www.{domain}'
    url = f'https://www.google.com/search?q={query}'
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    
    try:
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for link in soup.find_all('a'):
            href = link.get('href')
            if href.startswith('/url?q='):
                subdomain = href.split('/url?q=')[1].split('&')[0]
                if domain in subdomain and subdomain not in subdomains:
                    subdomains.add(subdomain)
    except requests.exceptions.RequestException as e:
        print(f'Error during Google dork: {e}')
    
    return subdomains

def ct_search(domain):
    """
    Search Certificate Transparency logs for subdomains.
    """
    subdomains = set()
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    
    try:
        response = requests.get(url)
        data = response.json()
        
        for entry in data:
            subdomain = entry['name_value']
            if subdomain.endswith(f'.{domain}') and subdomain not in subdomains:
                subdomains.add(subdomain)
    except requests.exceptions.RequestException as e:
        print(f'Error during CT search: {e}')
    
    return subdomains

def brute_force(domain, wordlist_path):
    """
    Perform dictionary brute-forcing to find subdomains.
    """
    subdomains = set()
    
    try:
        with open(wordlist_path, 'r') as wordlist:
            for word in wordlist:
                subdomain = word.strip() + '.' + domain
                if is_valid_subdomain(subdomain):
                    subdomains.add(subdomain)
    except FileNotFoundError:
        print(f'Error: Wordlist file not found at {wordlist_path}')
    except Exception as e:
        print(f'Error during brute-force: {e}')
    
    return subdomains

def is_valid_subdomain(subdomain):
    """
    Check if a subdomain is valid by attempting to resolve it.
    """
    try:
        response = requests.get(f'http://{subdomain}', timeout=2)
        return response.status_code < 400
    except requests.exceptions.RequestException:
        return False

def combine_results(results):
    """
    Combine the results from the different techniques and remove duplicates.
    """
    subdomains = set()
    for technique_results in results:
        subdomains.update(technique_results)
    return subdomains

def run_enumeration(domain, wordlist_path):
    """
    Run the subdomain enumeration process.
    """
    print(f'Starting subdomain enumeration for {domain}...')
    
    with ThreadPoolExecutor() as executor:
        results = [
            executor.submit(google_dork, domain),
            executor.submit(ct_search, domain),
            executor.submit(brute_force, domain, wordlist_path)
        ]
    
    subdomains = combine_results([result.result() for result in results])
    
    print(f'Discovered {len(subdomains)} subdomains:')
    for subdomain in subdomains:
        print(subdomain)
    
    return subdomains

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python subdomain_enumeration.py <domain> <wordlist_path>')
        sys.exit(1)
    
    domain = sys.argv[1]
    wordlist_path = sys.argv[2]
    
    run_enumeration(domain, wordlist_path)