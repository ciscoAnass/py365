import requests
import re
import ssl
import socket
import html
import urllib3
from urllib.parse import urlparse
from http.client import HTTPSConnection
from typing import Dict, List, Optional, Tuple
import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import webbrowser

class HeaderSecurityAnalyzer:
    def __init__(self):
        self.headers_scoring = {
            'Strict-Transport-Security': {
                'present': 10,
                'max_score': 15,
                'checks': [
                    ('max-age', 5),
                    ('includeSubDomains', 3),
                    ('preload', 2)
                ]
            },
            'X-XSS-Protection': {
                'present': 5,
                'max_score': 10,
                'checks': [
                    ('mode=block', 3),
                    ('report=', 2)
                ]
            },
            'Content-Security-Policy': {
                'present': 15,
                'max_score': 25,
                'checks': [
                    ('default-src', 5),
                    ('script-src', 5),
                    ('frame-ancestors', 5),
                    ('report-uri', 3),
                    ('strict-dynamic', 2)
                ]
            },
            'X-Frame-Options': {
                'present': 7,
                'max_score': 10,
                'checks': [
                    ('DENY', 5),
                    ('SAMEORIGIN', 3)
                ]
            },
            'X-Content-Type-Options': {
                'present': 5,
                'max_score': 5,
                'checks': [
                    ('nosniff', 5)
                ]
            }
        }

    def analyze_headers(self, url: str) -> Dict:
        try:
            urllib3.disable_warnings()
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            conn = HTTPSConnection(hostname, context=context, timeout=10)
            conn.request('HEAD', parsed_url.path or '/')
            response = conn.getresponse()
            headers = dict(response.getheaders())
            conn.close()

            return self._score_headers(headers)
        except Exception as e:
            return {'error': str(e)}

    def _score_headers(self, headers: Dict) -> Dict:
        results = {
            'total_score': 0,
            'max_possible_score': sum(details['max_score'] for details in self.headers_scoring.values()),
            'header_details': {}
        }

        for header_name, header_config in self.headers_scoring.items():
            header_result = {
                'present': False,
                'score': 0,
                'max_score': header_config['max_score'],
                'recommendations': []
            }

            if header_name in headers:
                header_result['present'] = True
                header_result['score'] += header_config['present']
                header_value = headers[header_name]

                for check_name, check_score in header_config.get('checks', []):
                    if check_name.lower() in header_value.lower():
                        header_result['score'] += check_score

            results['header_details'][header_name] = header_result
            results['total_score'] += header_result['score']

        return results

class SecurityAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Web Header Security Analyzer")
        master.geometry("800x600")

        self.url_label = tk.Label(master, text="Enter Website URL:")
        self.url_label.pack(pady=10)

        self.url_entry = tk.Entry(master, width=50)
        self.url_entry.pack(pady=5)
        self.url_entry.insert(0, "https://")

        self.analyze_button = tk.Button(master, text="Analyze Security Headers", command=self.start_analysis)
        self.analyze_button.pack(pady=10)

        self.results_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=80, height=20)
        self.results_text.pack(pady=10)

        self.analyzer = HeaderSecurityAnalyzer()

    def start_analysis(self):
        url = self.url_entry.get()
        self.results_text.delete(1.0, tk.END)
        threading.Thread(target=self.perform_analysis, args=(url,), daemon=True).start()

    def perform_analysis(self, url):
        try:
            results = self.analyzer.analyze_headers(url)
            self.display_results(results)
        except Exception as e:
            self.display_error(str(e))

    def display_results(self, results):
        def update_gui():
            if 'error' in results:
                self.results_text.insert(tk.END, f"Error: {results['error']}\n")
                return

            total_score = results['total_score']
            max_score = results['max_possible_score']
            percentage = (total_score / max_score) * 100 if max_score > 0 else 0

            self.results_text.insert(tk.END, f"Total Security Score: {total_score}/{max_score} ({percentage:.2f}%)\n\n")

            for header, details in results['header_details'].items():
                status = "✓" if details['present'] else "✗"
                self.results_text.insert(tk.END, f"{header} {status}: {details['score']}/{details['max_score']} points\n")

        self.master.after(0, update_gui)

    def display_error(self, error):
        def show_error():
            messagebox.showerror("Analysis Error", error)
        self.master.after(0, show_error)

def main():
    root = tk.Tk()
    app = SecurityAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()