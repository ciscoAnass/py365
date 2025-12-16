import os
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, urljoin
import re
from functools import wraps
import time

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

MAX_CONTENT_LENGTH = 16 * 1024 * 1024
MAX_TIMEOUT = 30
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.5
ALLOWED_SCHEMES = ('http', 'https')
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

class ScraperException(Exception):
    """Custom exception for scraper-related errors"""
    pass

class URLValidator:
    """Validates and sanitizes URLs"""
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        Validates if the provided URL is properly formatted
        
        Args:
            url: The URL string to validate
            
        Returns:
            Boolean indicating if URL is valid
        """
        try:
            result = urlparse(url)
            is_valid = all([
                result.scheme in ALLOWED_SCHEMES,
                result.netloc,
                len(url) < 2048
            ])
            return is_valid
        except Exception as e:
            logger.error(f"URL validation error: {str(e)}")
            return False
    
    @staticmethod
    def sanitize_url(url: str) -> str:
        """
        Sanitizes the URL by adding scheme if missing
        
        Args:
            url: The URL to sanitize
            
        Returns:
            Sanitized URL string
        """
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

class CSSSelector:
    """Handles CSS selector validation and processing"""
    
    @staticmethod
    def is_valid_selector(selector: str) -> bool:
        """
        Validates if the CSS selector is properly formatted
        
        Args:
            selector: The CSS selector string
            
        Returns:
            Boolean indicating if selector is valid
        """
        if not selector or not isinstance(selector, str):
            return False
        
        if len(selector) > 500:
            return False
        
        forbidden_chars = ['<', '>', '{', '}', ';']
        if any(char in selector for char in forbidden_chars):
            return False
        
        return True
    
    @staticmethod
    def normalize_selector(selector: str) -> str:
        """
        Normalizes the CSS selector
        
        Args:
            selector: The CSS selector to normalize
            
        Returns:
            Normalized selector string
        """
        return selector.strip()

class RequestManager:
    """Manages HTTP requests with retry logic and timeouts"""
    
    def __init__(self, timeout: int = MAX_TIMEOUT, max_retries: int = MAX_RETRIES):
        """
        Initializes the request manager
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """
        Creates a requests session with retry strategy
        
        Returns:
            Configured requests.Session object
        """
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=['GET', 'POST']
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        session.headers.update({
            'User-Agent': DEFAULT_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session
    
    def fetch_page(self, url: str) -> str:
        """
        Fetches the content of a webpage
        
        Args:
            url: The URL to fetch
            
        Returns:
            The HTML content of the page
            
        Raises:
            ScraperException: If the request fails
        """
        try:
            logger.info(f"Fetching URL: {url}")
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True
            )
            response.raise_for_status()
            
            if len(response.content) > MAX_CONTENT_LENGTH:
                raise ScraperException(f"Content size exceeds maximum allowed ({MAX_CONTENT_LENGTH} bytes)")
            
            logger.info(f"Successfully fetched {url} with status code {response.status_code}")
            return response.text
            
        except requests.exceptions.Timeout:
            raise ScraperException(f"Request timeout for URL: {url}")
        except requests.exceptions.ConnectionError:
            raise ScraperException(f"Connection error for URL: {url}")
        except requests.exceptions.HTTPError as e:
            raise ScraperException(f"HTTP error for URL {url}: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise ScraperException(f"Request failed for URL {url}: {str(e)}")
        except Exception as e:
            raise ScraperException(f"Unexpected error fetching URL {url}: {str(e)}")

class ContentExtractor:
    """Extracts content from HTML using CSS selectors"""
    
    @staticmethod
    def extract_elements(html_content: str, selector: str) -> List[Dict[str, Any]]:
        """
        Extracts elements from HTML using CSS selector
        
        Args:
            html_content: The HTML content to parse
            selector: The CSS selector to use
            
        Returns:
            List of dictionaries containing extracted element data
            
        Raises:
            ScraperException: If parsing fails
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            elements = soup.select(selector)
            
            if not elements:
                logger.warning(f"No elements found for selector: {selector}")
                return []
            
            extracted_data = []
            for idx, element in enumerate(elements):
                element_data = ContentExtractor._process_element(element, idx)
                extracted_data.append(element_data)
            
            logger.info(f"Extracted {len(extracted_data)} elements using selector: {selector}")
            return extracted_data
            
        except Exception as e:
            raise ScraperException(f"Error extracting elements: {str(e)}")
    
    @staticmethod
    def _process_element(element: Any, index: int) -> Dict[str, Any]:
        """
        Processes a single HTML element
        
        Args:
            element: The BeautifulSoup element to process
            index: The index of the element
            
        Returns:
            Dictionary containing processed element data
        """
        element_data = {
            'index': index,
            'tag': element.name,
            'text': element.get_text(strip=True),
            'html': str(element),
            'attributes': dict(element.attrs) if element.attrs else {}
        }
        
        if element.get('id'):
            element_data['id'] = element.get('id')
        
        if element.get('class'):
            element_data['classes'] = element.get('class', [])
        
        return element_data

class ScraperAPI:
    """Main API class for web scraping operations"""
    
    def __init__(self):
        """Initializes the scraper API"""
        self.request_manager = RequestManager()
        self.url_validator = URLValidator()
        self.css_selector = CSSSelector()
        self.content_extractor = ContentExtractor()
    
    def scrape(self, url: str, selector: str) -> Dict[str, Any]:
        """
        Performs the complete scraping operation
        
        Args:
            url: The URL to scrape
            selector: The CSS selector to use
            
        Returns:
            Dictionary containing scraping results
            
        Raises:
            ScraperException: If any step fails
        """
        start_time = time.time()
        
        url = self.url_validator.sanitize_url(url)
        
        if not self.url_validator.is_valid_url(url):
            raise ScraperException("Invalid URL format")
        
        selector = self.css_selector.normalize_selector(selector)
        
        if not self.css_selector.is_valid_selector(selector):
            raise ScraperException("Invalid CSS selector")
        
        html_content = self.request_manager.fetch_page(url)
        
        extracted_elements = self.content_extractor.extract_elements(html_content, selector)
        
        elapsed_time = time.time() - start_time
        
        result = {
            'success': True,
            'url': url,
            'selector': selector,
            'elements_found': len(extracted_elements),
            'elements': extracted_elements,
            'timestamp': datetime.utcnow().isoformat(),
            'execution_time_seconds': round(elapsed_time, 3)
        }
        
        return result

scraper_api = ScraperAPI()

def validate_request_data(f):
    """Decorator to validate incoming request data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Request must be JSON'
            }), 400
        
        data = request.get_json()
        
        if not isinstance(data, dict):
            return jsonify({
                'success': False,
                'error': 'Request body must be a JSON object'
            }), 400
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    
    Returns:
        JSON response indicating API health status
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'web-scraper-api'
    }), 200

@app.route('/scrape', methods=['POST'])
@validate_request_data
def scrape_endpoint():
    """
    Main scraping endpoint
    
    Expected JSON payload:
    {
        "url": "https://example.com",
        "selector": "h2"
    }
    
    Returns:
        JSON response with scraped data or error message
    """
    try:
        data = request.get_json()
        
        url = data.get('url', '').strip()
        selector = data.get('selector', '').strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL is required'
            }), 400
        
        if not selector:
            return jsonify({
                'success': False,
                'error': 'CSS selector is required'
            }), 400
        
        result = scraper_api.scrape(url, selector)
        
        return jsonify(result), 200
        
    except ScraperException as e:
        logger.error(f"Scraper error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 400
    
    except Exception as e:
        logger.error(f"Unexpected error in scrape endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred',
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/scrape/batch', methods=['POST'])
@validate_request_data
def scrape_batch_endpoint():
    """
    Batch scraping endpoint for multiple URLs
    
    Expected JSON payload:
    {
        "requests": [
            {"url": "https://example.com", "selector": "h2"},
            {"url": "https://example.org", "selector": "p"}
        ]
    }
    
    Returns:
        JSON response with results for each scraping request
    """
    try:
        data = request.get_json()
        
        requests_list = data.get('requests', [])
        
        if not isinstance(requests_list, list):
            return jsonify({
                'success': False,
                'error': 'requests must be a list'
            }), 400
        
        if not requests_list:
            return jsonify({
                'success': False,
                'error': 'requests list cannot be empty'
            }), 400
        
        if len(requests_list) > 10:
            return jsonify({
                'success': False,
                'error': 'Maximum 10 requests per batch'
            }), 400
        
        results = []
        
        for idx, req in enumerate(requests_list):
            try:
                url = req.get('url', '').strip()
                selector = req.get('selector', '').strip()
                
                if not url or not selector:
                    results.append({
                        'index': idx,
                        'success': False,
                        'error': 'URL and selector are required'
                    })
                    continue
                
                result = scraper_api.scrape(url, selector)
                result['index'] = idx
                results.append(result)
                
            except ScraperException as e:
                results.append({
                    'index': idx,
                    'success': False,
                    'error': str(e)
                })
            except Exception as e:
                results.append({
                    'index': idx,
                    'success': False,
                    'error': 'Unexpected error'
                })
        
        return jsonify({
            'success': True,
            'total_requests': len(requests_list),
            'results': results,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Unexpected error in batch scrape endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred',
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/validate', methods=['POST'])
@validate_request_data
def validate_endpoint():
    """
    Validation endpoint for URLs and selectors
    
    Expected JSON payload:
    {
        "url": "https://example.com",
        "selector": "h2"
    }
    
    Returns:
        JSON response with validation results
    """