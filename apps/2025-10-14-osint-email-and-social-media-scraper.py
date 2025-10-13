import re
import requests
from bs4 import BeautifulSoup
import urllib.parse
import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import queue
import json
import logging
import ssl
import socket
import concurrent.futures

class OSINTScraper:
    def __init__(self):
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.social_patterns = {
            'facebook': re.compile(r'facebook\.com/[a-zA-Z0-9.-]+'),
            'twitter': re.compile(r'twitter\.com/[a-zA-Z0-9_]+'),
            'linkedin': re.compile(r'linkedin\.com/in/[a-zA-Z0-9.-]+'),
            'instagram': re.compile(r'instagram\.com/[a-zA-Z0-9._]+')
        }
        self.results_queue = queue.Queue()
        self.logger = self._setup_logging()
        self.setup_ui()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler('osint_scraper.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def setup_ui(self):
        self.root = tk.Tk()
        self.root.title("OSINT Email & Social Media Scraper")
        self.root.geometry("800x600")

        tk.Label(self.root, text="Target Website URL:").pack(pady=10)
        self.url_entry = tk.Entry(self.root, width=70)
        self.url_entry.pack(pady=5)

        tk.Button(self.root, text="Start Scraping", command=self.start_scraping).pack(pady=10)

        self.results_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20)
        self.results_text.pack(pady=10)

    def start_scraping(self):
        target_url = self.url_entry.get()
        if not target_url:
            messagebox.showerror("Error", "Please enter a valid URL")
            return

        self.results_text.delete(1.0, tk.END)
        threading.Thread(target=self.scrape_website, args=(target_url,), daemon=True).start()
        self.root.after(100, self.update_results)

    def scrape_website(self, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            
            emails = self.extract_emails(response.text)
            social_profiles = self.extract_social_profiles(response.text)
            links = self.extract_links(soup, url)

            results = {
                'emails': list(set(emails)),
                'social_profiles': social_profiles,
                'links': list(set(links))
            }

            self.results_queue.put(results)
            self.logger.info(f"Scraped {url}: Found {len(emails)} emails, {len(social_profiles)} social profiles")

        except requests.RequestException as e:
            self.results_queue.put({'error': str(e)})
            self.logger.error(f"Scraping error for {url}: {e}")

    def extract_emails(self, text):
        return self.email_pattern.findall(text)

    def extract_social_profiles(self, text):
        profiles = {}
        for platform, pattern in self.social_patterns.items():
            matches = pattern.findall(text)
            if matches:
                profiles[platform] = list(set(matches))
        return profiles

    def extract_links(self, soup, base_url):
        links = []
        for link in soup.find_all('a', href=True):
            absolute_url = urllib.parse.urljoin(base_url, link['href'])
            links.append(absolute_url)
        return links

    def update_results(self):
        try:
            results = self.results_queue.get_nowait()
            if 'error' in results:
                messagebox.showerror("Scraping Error", results['error'])
            else:
                self.results_text.insert(tk.END, "Emails Found:\n")
                for email in results.get('emails', []):
                    self.results_text.insert(tk.END, f"{email}\n")

                self.results_text.insert(tk.END, "\nSocial Profiles:\n")
                for platform, profiles in results.get('social_profiles', {}).items():
                    self.results_text.insert(tk.END, f"{platform.capitalize()}: {', '.join(profiles)}\n")

                self.results_text.insert(tk.END, "\nLinks:\n")
                for link in results.get('links', [])[:20]:  # Limit to first 20 links
                    self.results_text.insert(tk.END, f"{link}\n")

        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.update_results)

    def run(self):
        self.root.mainloop()

def main():
    scraper = OSINTScraper()
    scraper.run()

if __name__ == "__main__":
    main()