import imaplib
import email
import ssl
import re
import logging
import time
import json
import requests
import os
import datetime

class PhishingReporterConfiguration:
    def __init__(self):
        self.imap_server = os.environ.get('IMAP_SERVER', 'imap.example.com')
        self.imap_port = int(os.environ.get('IMAP_PORT', 993))
        self.imap_username = os.environ.get('IMAP_USERNAME', 'phishing@company.com')
        self.imap_password = os.environ.get('IMAP_PASSWORD', 'your_password_here')
        self.inbox_folder = os.environ.get('INBOX_FOLDER', 'INBOX')
        self.archive_folder = os.environ.get('ARCHIVE_FOLDER', 'PhishingArchive')
        self.virustotal_api_key = os.environ.get('VIRUSTOTAL_API_KEY', 'YOUR_VIRUSTOTAL_API_KEY')
        self.virustotal_url_scan_endpoint = os.environ.get('VIRUSTOTAL_URL_SCAN_ENDPOINT', 'https://www.virustotal.com/api/v3/urls')
        self.virustotal_report_endpoint = os.environ.get('VIRUSTOTAL_REPORT_ENDPOINT', 'https://www.virustotal.com/api/v3/analyses/')
        self.processing_interval_seconds = int(os.environ.get('PROCESSING_INTERVAL_SECONDS', 300))
        self.max_retries = int(os.environ.get('MAX_RETRIES', 5))
        self.retry_delay_seconds = int(os.environ.get('RETRY_DELAY_SECONDS', 10))
        self.log_file_path = os.environ.get('LOG_FILE_PATH', 'phishing_reporter.log')
        self.log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
        self.allowed_forward_senders = os.environ.get('ALLOWED_FORWARD_SENDERS', 'security@company.com,itsupport@company.com').split(',')

class PhishingEmailProcessor:
    def __init__(self, config):
        self._config = config
        self._setup_logging()

    def _setup_logging(self):
        self._logger = logging.getLogger('PhishingReporter')
        self._logger.setLevel(self._config.log_level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler = logging.FileHandler(self._config.log_file_path)
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)

    def _extract_original_content_from_forwarded_email(self, msg):
        original_text_content = ""
        original_html_content = ""
        forward_delimiters = [
            "-----Original Message-----",
            "-------- Forwarded Message --------",
            "From: ",
            "Sent: ",
            "To: ",
            "Subject: ",
            "X-Original-Message-ID:",
            "Begin forwarded message:",
            "On ",
            " wrote:",
            "\nSubject: ",
            "\nTo: ",
            "\nFrom: ",
            "\nDate: ",
        ]

        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                payload = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                for delimiter in forward_delimiters:
                    if delimiter in payload:
                        original_text_content = payload.split(delimiter, 1)[1].strip()
                        return original_text_content, original_html_content
                original_text_content = payload
            elif content_type == 'text/html':
                payload = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                for delimiter in forward_delimiters:
                    if delimiter in payload:
                        original_html_content = payload.split(delimiter, 1)[1].strip()
                        return original_text_content, original_html_content
                original_html_content = payload
        return original_text_content, original_html_content

    def _extract_urls_from_text(self, text_content):
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        found_urls = set(url_pattern.findall(text_content))
        return list(found_urls)

    def _extract_all_headers(self, msg):
        headers = {}
        for header_name, header_value in msg.items():
            headers[header_name] = header_value
        return headers

    def _get_original_sender_info(self, headers, original_body_text):
        original_sender_email = "unknown@example.com"
        original_sender_name = "Unknown"
        original_subject = headers.get('Subject', 'No Subject')

        subject_match = re.search(r"^\s*(Re:|Fwd:|FW:|Fw:)\s*(.*)", original_subject, re.IGNORECASE)
        if subject_match:
            original_subject = subject_match.group(2).strip()

        from_header_match = re.search(r"From:\s*(.+?)\s*<(.*?)>", original_body_text, re.IGNORECASE)
        if from_header_match:
            original_sender_name = from_header_match.group(1).strip()
            original_sender_email = from_header_match.group(2).strip()
            return original_sender_email, original_sender_name, original_subject

        from_header_match_simple = re.search(r"From:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", original_body_text, re.IGNORECASE)
        if from_header_match_simple:
            original_sender_email = from_header_match_simple.group(1).strip()
            return original_sender_email, original_sender_name, original_subject

        try:
            from_header_value = headers.get('From', '')
            match = re.search(r"<(.*?)>", from_header_value)
            if match:
                original_sender_email = match.group(1)
            else:
                original_sender_email = from_header_value
        except Exception as e:
            self._logger.error(f"Error parsing top-level 'From' header: {e}")

        return original_sender_email, original_sender_name, original_subject

    def _submit_url_to_virustotal(self, url):
        if not self._config.virustotal_api_key or self._config.virustotal_api_key == 'YOUR_VIRUSTOTAL_API_KEY':
            return {"scan_result": "skipped", "reason": "API key missing or placeholder"}

        headers = {
            "x-apikey": self._config.virustotal_api_key,
            "Accept": "application/json"
        }
        data = {'url': url}
        
        try:
            response = requests.post(self._config.virustotal_url_scan_endpoint, headers=headers, data=data)
            response.raise_for_status()
            analysis_id = response.json().get('data', {}).get('id')
            if analysis_id:
                return self._get_virustotal_report(analysis_id)
            else:
                return {"scan_result": "error", "reason": "No analysis ID"}
        except requests.exceptions.RequestException as e:
            return {"scan_result": "error", "reason": str(e)}

    def _get_virustotal_report(self, analysis_id, max_attempts=5, delay=10):
        headers = {
            "x-apikey": self._config.virustotal_api_key,
            "Accept": "application/json"
        }
        report_url = f"{self._config.virustotal_report_endpoint}{analysis_id}"

        for attempt in range(max_attempts):
            time.sleep(delay)
            try:
                response = requests.get(report_url, headers=headers)
                response.raise_for_status()
                report_data = response.json()
                status = report_data.get('data', {}).get('attributes', {}).get('status')
                if status == 'completed':
                    results = report_data.get('data', {}).get('attributes', {}).get('results', {})
                    malicious_count = sum(1 for res in results.values() if res.get('category') == 'malicious')
                    return {"scan_result": "completed", "malicious_count": malicious_count, "details": results}
                elif status == 'queued' or status == 'in-progress':
                    pass
                else:
                    return {"scan_result": "error", "reason": f"VirusTotal report status: {status}"}
            except requests.exceptions.RequestException as e:
                return {"scan_result": "error", "reason": str(e)}
        return {"scan_result": "timeout", "reason": "Report not ready after multiple attempts"}

    def _analyze_email_headers_for_anomalies(self, headers):
        analysis_results = {
            "header_present": False,
            "spoofing_risk": "low",
            "spf_result": "none",
            "dkim_result": "none",
            "dmarc_result": "none",
            "return_path": headers.get('Return-Path', 'N/A'),
            "received_ips": [],
            "received_domains": [],
            "message_id": headers.get('Message-ID', 'N/A'),
            "subject": headers.get('Subject', 'N/A'),
            "from_header": headers.get('From', 'N/A'),
        }

        if headers:
            analysis_results["header_present"] = True

        for header_name, header_value in headers.items():
            if header_name.lower() == 'received':
                ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header_value)
                if ip_match:
                    analysis_results["received_ips"].append(ip_match.group(1))
                domain_match = re.search(r'from\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', header_value)
                if domain_match:
                    analysis_results["received_domains"].append(domain_match.group(1))
            elif header_name.lower() == 'authentication-results':
                if 'spf=' in header_value:
                    spf_match = re.search(r'spf=(\w+)', header_value)
                    if spf_match:
                        analysis_results["spf_result"] = spf_match.group(1)
                if 'dkim=' in header_value:
                    dkim_match = re.search(r'dkim=(\w+)', header_value)
                    if dkim_match:
                        analysis_results["dkim_result"] = dkim_match.group(1)
                if 'dmarc=' in header_value:
                    dmarc_match = re.search(r'dmarc=(\w+)', header_value)
                    if dmarc_match:
                        analysis_results["dmarc_result"] = dmarc_match.group(1)
        
        from_email_match = re.search(r"<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>", headers.get('From', ''))
        from_domain = ""
        if from_email_match:
            from_domain = from_email_match.group(1).split('@')[-1]

        if analysis_results["spf_result"] == "fail" or analysis_results["dkim_result"] == "fail":
            analysis_results["spoofing_risk"] = "high"
        elif analysis_results["dmarc_result"] == "fail":
            analysis_results["spoofing_risk"] = "critical"
        elif from_domain and from_domain not in analysis_results["received_domains"]:
             analysis_results["spoofing_risk"] = "medium"

        return analysis_results

    def process_email_message(self, email_message_bytes):
        msg = email.message_from_bytes(email_message_bytes)

        full_headers = self._extract_all_headers(msg)
        subject = full_headers.get('Subject', 'No Subject')
        sender = full_headers.get('From', 'No Sender')
        date_received = full_headers.get('Date', 'No Date')

        is_forwarded_subject = subject.lower().startswith('fwd:') or subject.lower().startswith('fw:')
        
        forward_sender_match = False
        for allowed_sender in self._config.allowed_forward_senders:
            if allowed_sender.lower() in sender.lower():
                forward_sender_match = True
                break
        
        if not is_forwarded_subject and not forward_sender_match:
            return {
                "status": "skipped_not_forwarded",
                "original_subject": subject,
                "original_sender_email": sender,
                "date_received": date_received,
                "summary": "Email does not match forwarded email criteria (subject or sender).",
                "urls_scans": [],
                "header_analysis": {}
            }

        original_text_content, original_html_content = self._extract_original_content_from_forwarded_email(msg)

        all_extracted_urls = set()
        if original_text_content:
            all_extracted_urls.update(self._extract_urls_from_text(original_text_content))
        if original_html_content:
            all_extracted_urls.update(self._extract_urls_from_text(original_html_content))
        
        original_sender_email, original_sender_name, original_subject = self._get_original_sender_info(full_headers, original_text_content)

        url_scan_results = []
        for url in all_extracted_urls:
            scan_report = self._submit_url_to_virustotal(url)
            url_scan_results.append({"url": url, "report": scan_report})

        header_analysis_results = self._analyze_email_headers_for_anomalies(full_headers)

        overall_risk_score = 0
        if header_analysis_results["spoofing_risk"] == "critical":
            overall_risk_score += 100
        elif header_analysis_results["spoofing_risk"] == "high":
            overall_risk_score += 50
        elif header_analysis_results["spoofing_risk"] == "medium":
            overall_risk_score += 20
        
        for url_result in url_scan_results:
            if url_result["report"].get("malicious_count", 0) > 0:
                overall_risk_score += (url_result["report"]["malicious_count"] * 10)

        return {
            "status": "processed",
            "original_subject": original_subject,
            "original_sender_email": original_sender_email,
            "original_sender_name": original_sender_name,
            "date_received": date_received,
            "extracted_urls": list(all_extracted_urls),
            "urls_scans": url_scan_results,
            "header_analysis": header_analysis_results,
            "overall_risk_score": overall_risk_score,
            "processing_timestamp": datetime.datetime.now().isoformat()
        }


class PhishingEmailReporter:
    def __init__(self, config):
        self._config = config
        self._setup_logging()
        self._imap = None
        self._email_processor = PhishingEmailProcessor(config)

    def _setup_logging(self):
        self._logger = logging.getLogger('PhishingReporter')
        self._logger.setLevel(self._config.log_level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler = logging.FileHandler(self._config.log_file_path)
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)

    def _connect_to_imap(self):
        for attempt in range(self._config.max_retries):
            try:
                context = ssl.create_default_context()
                self._imap = imaplib.IMAP4_SSL(self._config.imap_server, self._config.imap_port, ssl_context=context)
                self._imap.login(self._config.imap_username, self._config.imap_password)
                return True
            except imaplib.IMAP4.error as e:
                self._logger.error(f"IMAP login failed: {e}. Attempt {attempt + 1}/{self._config.max_retries}. Retrying in {self._config.retry_delay_seconds} seconds.")
                self._imap = None
                time.sleep(self._config.retry_delay_seconds)
            except Exception as e:
                self._logger.critical(f"An unexpected error occurred during IMAP connection: {e}. Attempt {attempt + 1}/{self._config.max_retries}. Retrying in {self._config.retry_delay_seconds} seconds.")
                self._imap = None
                time.sleep(self._config.retry_delay_seconds)
        return False

    def _disconnect_from_imap(self):
        if self._imap:
            try:
                self._imap.logout()
            except Exception as e:
                self._logger.error(f"Error during IMAP logout: {e}")
            finally:
                self._imap = None

    def _ensure_archive_folder_exists(self):
        try:
            status, folders = self._imap.list()
            if status != 'OK':
                return False
            
            archive_folder_exists = False
            for folder_bytes in folders:
                folder_str = folder_bytes.decode('utf-8')
                if self._config.archive_folder in folder_str:
                    archive_folder_exists = True
                    break
            
            if not archive_folder_exists:
                status, create_response = self._imap.create(self._config.archive_folder)
                if status == 'OK':
                    return True
                else:
                    return False
            return True
        except Exception as e:
            self._logger.error(f"Error checking/creating archive folder: {e}")
            return False

    def _fetch_unread_emails(self):
        status, messages = self._imap.select(self._config.inbox_folder)
        if status != 'OK':
            return []

        status, email_ids = self._imap.search(None, 'UNSEEN')
        if status != 'OK':
            return []

        email_id_list = email_ids[0].split()
        
        fetched_emails = []
        for email_id in email_id_list:
            try:
                status, msg_data = self._imap.fetch(email_id, '(RFC822)')
                if status == 'OK':
                    raw_email = msg_data[0][1]
                    fetched_emails.append((email_id, raw_email))
                else:
                    self._logger.warning(f"Failed to fetch email ID {email_id}: {msg_data}")
            except Exception as e:
                self._logger.error(f"Error fetching email ID {email_id}: {e}")
        return fetched_emails

    def _archive_email(self, email_id):
        try:
            status, copy_response = self._imap.copy(email_id, self._config.archive_folder)
            if status == 'OK':
                status, delete_response = self._imap.store(email_id, '+FLAGS', '\\Deleted')
                if status == 'OK':
                    self._imap.expunge()
                    return True
                else:
                    self._logger.error(f"Failed to mark email ID {email_id} for deletion: {delete_response}")
            else:
                self._logger.error(f"Failed to copy email ID {email_id} to archive: {copy_response}")
        except Exception as e:
            self._logger.error(f"Error archiving email ID {email_id}: {e}")
        return False

    def run_reporter_cycle(self):
        if not self._connect_to_imap():
            return

        if not self._ensure_archive_folder_exists():
            self._logger.error("Could not ensure archive folder exists. Proceeding with caution, but archiving might fail.")

        try:
            emails_to_process = self._fetch_unread_emails()
            if not emails_to_process:
                return

            for email_id, raw_email_bytes in emails_to_process:
                try:
                    processing_results = self._email_processor.process_email_message(raw_email_bytes)
                    
                    if processing_results.get("status") == "processed":
                        self._archive_email(email_id)
                    elif processing_results.get("status") == "skipped_not_forwarded":
                         self._imap.store(email_id, '+FLAGS', '\\Seen')
                    else:
                        self._imap.store(email_id, '+FLAGS', '\\Seen')
                except Exception as e:
                    self._logger.error(f"Critical error processing email ID {email_id.decode('utf-8')}: {e}", exc_info=True)
                    try:
                        self._imap.store(email_id, '+FLAGS', '\\Seen')
                    except Exception as e_mark:
                        self._logger.error(f"Failed to mark email {email_id.decode('utf-8')} as seen after critical error: {e_mark}")
        except Exception as e:
            self._logger.critical(f"An unexpected error occurred during the main reporter cycle: {e}", exc_info=True)
        finally:
            self._disconnect_from_imap()

def main_execution_loop():
    config = PhishingReporterConfiguration()
    reporter = PhishingEmailReporter(config)
    
    main_logger = logging.getLogger('PhishingReporter')

    try:
        while True:
            reporter.run_reporter_cycle()
            time.sleep(config.processing_interval_seconds)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        main_logger.critical(f"Main execution loop encountered a critical error: {e}", exc_info=True)

if __name__ == '__main__':
    main_execution_loop()