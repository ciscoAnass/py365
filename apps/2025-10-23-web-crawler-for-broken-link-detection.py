import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import concurrent.futures
import logging
import sys
import re
from typing import List, Dict, Set
from dataclasses import dataclass, field

@dataclass
class LinkReport:
    total_links: int = 0
    broken_links: List[Dict[str, str]] = field(default_factory=list)
    visited_urls: Set[str] = field(default_factory=set)

class WebCrawler:
    def __init__(self, start_url: str, max_depth: int = 3, max_workers: int = 10):
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.report = LinkReport()
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)

    def is_valid_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def is_same_domain(self, base_url: str, target_url: str) -> bool:
        base_domain = urlparse(base_url).netloc
        target_domain = urlparse(target_url).netloc
        return base_domain == target_domain

    def normalize_url(self, base_url: str, href: str) -> str:
        return urljoin(base_url, href)

    def check_link_status(self, url: str) -> int:
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            return response.status_code
        except (requests.RequestException, Exception) as e:
            self.logger.warning(f"Error checking {url}: {e}")
            return 500

    def extract_links(self, html_content: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = self.normalize_url(base_url, href)
            if self.is_valid_url(full_url) and self.is_same_domain(base_url, full_url):
                links.append(full_url)
        return links

    def crawl_page(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.report.visited_urls:
            return

        self.report.visited_urls.add(url)
        self.logger.info(f"Crawling: {url} (Depth: {depth})")

        try:
            response = requests.get(url, timeout=10)
            status_code = response.status_code

            self.report.total_links += 1
            if status_code >= 400:
                self.report.broken_links.append({
                    'url': url,
                    'status_code': status_code
                })
                self.logger.warning(f"Broken Link: {url} (Status: {status_code})")

            if depth < self.max_depth:
                links = self.extract_links(response.text, url)
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    executor.map(lambda link: self.crawl_page(link, depth + 1), links)

        except requests.RequestException as e:
            self.logger.error(f"Error crawling {url}: {e}")
            self.report.broken_links.append({
                'url': url,
                'status_code': 500
            })

    def generate_html_report(self) -> str:
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Crawler Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: auto; }}
                h1 {{ color: #333; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .total {{ color: blue; }}
                .broken {{ color: red; }}
            </style>
        </head>
        <body>
            <h1>Web Crawler Report</h1>
            <p>Start URL: {self.start_url}</p>
            <p>Total Links Checked: <span class="total">{self.report.total_links}</span></p>
            <p>Broken Links: <span class="broken">{len(self.report.broken_links)}</span></p>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Status Code</th>
                </tr>
                {''.join(f'<tr><td>{link["url"]}</td><td>{link["status_code"]}</td></tr>' for link in self.report.broken_links)}
            </table>
        </body>
        </html>
        """
        return html_template

    def run(self) -> None:
        self.crawl_page(self.start_url)
        report_html = self.generate_html_report()
        
        with open('crawler_report.html', 'w') as f:
            f.write(report_html)
        
        self.logger.info("Crawling completed. Report generated.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python crawler.py <start_url>")
        sys.exit(1)

    start_url = sys.argv[1]
    crawler = WebCrawler(start_url, max_depth=3, max_workers=10)
    crawler.run()

if __name__ == "__main__":
    main()