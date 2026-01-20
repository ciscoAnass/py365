import requests
import argparse
import sys
import re
from urllib.parse import urlparse, urlunparse

# --- Configuration and Constants ---

# ANSI escape codes for colored output
# These codes allow printing text in different colors in the terminal,
# enhancing readability of the report.
class Color:
    HEADER = '\033[95m'    # Purple for main titles
    OKBLUE = '\033[94m'    # Blue for informational messages and sections
    OKCYAN = '\033[96m'    # Cyan for sub-sections and low severity
    OKGREEN = '\033[92m'   # Green for success messages and good findings
    WARNING = '\033[93m'   # Yellow for warnings and medium severity
    FAIL = '\033[91m'      # Red for errors, critical/high severity
    ENDC = '\033[0m'       # Resets color to default
    BOLD = '\033[1m'       # Bold text
    UNDERLINE = '\033[4m'  # Underlined text

# Severity levels for reporting findings.
# These help categorize the impact of missing or misconfigured headers.
class Severity:
    CRITICAL = "CRITICAL"  # Highest severity, must be addressed immediately
    HIGH = "HIGH"          # Significant security risk
    MEDIUM = "MEDIUM"      # Moderate security risk, recommended to fix
    LOW = "LOW"            # Minor security improvement
    INFO = "INFO"          # Informational, good practice, or not a direct vulnerability
    GOOD = "GOOD"          # Header is present and configured correctly

# Define a structure for reporting security findings.
# This object-oriented approach makes it easier to manage and display each finding's details.
class SecurityFinding:
    """
    Represents a single security finding related to an HTTP header.
    Attributes:
        header_name (str): The name of the HTTP header being analyzed (e.g., 'Content-Security-Policy').
        status (str): The status of the finding (e.g., "MISSING", "PRESENT_OK", "MISCONFIGURED", "PRESENT_WEAK").
        severity (str): The severity level of the finding (e.g., Severity.HIGH).
        details (str): A detailed description of the finding.
        actual_value (str, optional): The actual value of the header found in the response. Defaults to None.
        recommendation (str, optional): Actionable advice for remediation. Defaults to None.
    """
    def __init__(self, header_name, status, severity, details, actual_value=None, recommendation=None):
        self.header_name = header_name
        self.status = status
        self.severity = severity
        self.details = details
        self.actual_value = actual_value
        self.recommendation = recommendation

    def __str__(self):
        """
        Returns a formatted string representation of the finding, including color-coding.
        """
        # Determine color based on the status of the header
        status_color = Color.OKGREEN
        if self.status == "MISSING":
            status_color = Color.FAIL
        elif self.status == "MISCONFIGURED":
            status_color = Color.WARNING
        elif self.status == "PRESENT_WEAK":
            status_color = Color.WARNING
        elif self.status == "ERROR_DURING_ANALYSIS":
            status_color = Color.FAIL
        
        # Determine color based on the severity of the finding
        severity_color = Color.OKGREEN
        if self.severity == Severity.CRITICAL or self.severity == Severity.HIGH:
            severity_color = Color.FAIL
        elif self.severity == Severity.MEDIUM:
            severity_color = Color.WARNING
        elif self.severity == Severity.LOW:
            severity_color = Color.OKCYAN
        elif self.severity == Severity.INFO:
            severity_color = Color.OKBLUE

        # Construct the detailed output string
        output = f"  {Color.BOLD}Header:{Color.ENDC} {self.header_name}\n"
        output += f"    {Color.BOLD}Status:{Color.ENDC} {status_color}{self.status}{Color.ENDC}\n"
        output += f"    {Color.BOLD}Severity:{Color.ENDC} {severity_color}{self.severity}{Color.ENDC}\n"
        output += f"    {Color.BOLD}Details:{Color.ENDC} {self.details}\n"
        if self.actual_value is not None:
            output += f"    {Color.BOLD}Actual Value:{Color.ENDC} {self.actual_value}\n"
        if self.recommendation:
            output += f"    {Color.BOLD}Recommendation:{Color.ENDC} {self.recommendation}\n"
        return output

# --- Utility Functions for Output Formatting ---

def print_separator(char='=', length=80, color=Color.HEADER):
    """
    Prints a separator line to visually segment different parts of the report.
    Args:
        char (str): The character to use for the separator.
        length (int): The total length of the separator line.
        color (str): The ANSI color code for the separator.
    """
    print(f"{color}{char * length}{Color.ENDC}")

def print_title(title_text, char='=', length=80, color=Color.HEADER):
    """
    Prints a large, formatted title for major sections of the report.
    Args:
        title_text (str): The text of the title.
        char (str): The character to use for the separator lines above and below the title.
        length (int): The total width of the title block.
        color (str): The ANSI color code for the title.
    """
    print_separator(char, length, color)
    # Center the title text within the given length
    print(f"{color}{' ' * ((length - len(title_text)) // 2)}{title_text}{Color.ENDC}")
    print_separator(char, length, color)

def print_section(section_text, char='-', length=80, color=Color.OKBLUE):
    """
    Prints a formatted section header.
    Args:
        section_text (str): The text for the section header.
        char (str): The character to use for the line before and after the text.
        length (int): The total width of the section header.
        color (str): The ANSI color code for the section header.
    """
    print(f"\n{color}{char * 3} {section_text} {char * (length - len(section_text) - 6)}{Color.ENDC}")

def print_sub_section(sub_section_text, char='.', length=80, color=Color.OKCYAN):
    """
    Prints a formatted sub-section header.
    Args:
        sub_section_text (str): The text for the sub-section header.
        char (str): The character to use for the line before and after the text.
        length (int): The total width of the sub-section header.
        color (str): The ANSI color code for the sub-section header.
    """
    print(f"\n  {color}{char * 2} {sub_section_text} {char * (length - len(sub_section_text) - 7)}{Color.ENDC}")

# --- Core Request Functionality ---

def fetch_url_headers(target_url, allow_redirects=True, timeout=10):
    """
    Fetches HTTP response headers for a given URL using the requests library.
    Handles network errors and timeouts gracefully.

    Args:
        target_url (str): The URL to make a GET request to.
        allow_redirects (bool): If True, follow HTTP redirects. If False, process the initial response.
        timeout (int): The maximum number of seconds to wait for a response.

    Returns:
        tuple: A tuple containing:
            - dict: Normalized dictionary of response headers (keys are title-cased).
            - int: The HTTP status code of the final response (or 0 if an error occurred).
            - str: The final URL after any redirects.
            - requests.Response or None: The raw requests.Response object, or None if an error occurred.
            - str or None: An error message if the request failed, otherwise None.
    """
    print(f"{Color.OKBLUE}Attempting to fetch headers from: {target_url}{Color.ENDC}")
    try:
        # Define a User-Agent to identify the scanner. This is good practice
        # and helps avoid being blocked by some web servers or WAFs.
        headers = {
            'User-Agent': 'Automated-Security-Headers-Checker/1.0 (+https://github.com/your-repo-link-here)'
        }
        
        # Make the actual GET request.
        # `verify=True` ensures SSL certificates are validated.
        response = requests.get(target_url, allow_redirects=allow_redirects, timeout=timeout, headers=headers, verify=True)
        
        # Normalize header keys to Title-Case (e.g., 'content-type' becomes 'Content-Type').
        # This makes header lookups consistent, regardless of how the server sends them.
        normalized_headers = {k.title(): v for k, v in response.headers.items()}
        
        print(f"{Color.OKGREEN}Successfully fetched headers. Final URL: {response.url}, Status Code: {response.status_code}{Color.ENDC}")
        return normalized_headers, response.status_code, response.url, response, None
    except requests.exceptions.Timeout:
        error_msg = f"{Color.FAIL}Error: Request timed out after {timeout} seconds for {target_url}{Color.ENDC}"
        print(error_msg)
        return {}, 0, target_url, None, error_msg
    except requests.exceptions.ConnectionError as e:
        error_msg = f"{Color.FAIL}Error: Could not connect to {target_url}. Check URL or network connection. Details: {e}{Color.ENDC}"
        print(error_msg)
        return {}, 0, target_url, None, error_msg
    except requests.exceptions.HTTPError as e:
        # Catches HTTP errors like 404, 500, etc. that are not successful (2xx).
        error_msg = f"{Color.FAIL}Error: HTTP error occurred for {target_url}. Status: {e.response.status_code}. Details: {e}{Color.ENDC}"
        print(error_msg)
        return {}, e.response.status_code, target_url, None, error_msg
    except requests.exceptions.RequestException as e:
        # Catches any other requests-related exceptions (e.g., too many redirects).
        error_msg = f"{Color.FAIL}An unexpected request error occurred for {target_url}. Details: {e}{Color.ENDC}"
        print(error_msg)
        return {}, 0, target_url, None, error_msg
    except Exception as e:
        # Catch any other unforeseen exceptions during the request process.
        error_msg = f"{Color.FAIL}An unforeseen error occurred during header retrieval: {e}{Color.ENDC}"
        print(error_msg)
        return {}, 0, target_url, None, error_msg


# --- Individual Header Analysis Functions ---

def analyze_cookies_security(headers, final_url):
    """
    Analyzes 'Set-Cookie' headers for security flags (HttpOnly, Secure, SameSite).
    Args:
        headers (dict): Normalized HTTP response headers.
        final_url (str): The final URL after redirects, used to check if HTTPS is in use.
    Returns:
        list: A list of SecurityFinding objects, one for each cookie or a summary.
    """
    findings = []
    # Retrieve all 'Set-Cookie' headers. A response can have multiple 'Set-Cookie' headers.
    # requests.Response.headers.get('Set-Cookie') will return a single string if only one
    # or a comma-separated string if multiple, or None. We need to parse robustly.
    set_cookie_headers = headers.get('Set-Cookie')

    if not set_cookie_headers:
        findings.append(
            SecurityFinding(
                "Set-Cookie",
                "MISSING_COOKIES",
                Severity.INFO,
                "No 'Set-Cookie' headers found. This might mean the application doesn't set cookies, "
                "or they are handled differently. If cookies are expected, this could indicate an issue.",
                "N/A",
                "Verify if your application is designed to use cookies. If not, this finding is informational. "
                "If cookies are used, ensure they are set correctly."
            )
        )
        return findings

    # Split the combined 'Set-Cookie' header string into individual cookie strings.
    # This regex attempts to split by comma followed by a space, unless the comma is part of a quoted string.
    # This is a common heuristic but might not cover all edge cases with complex cookie values.
    # For robust parsing, one might need a dedicated cookie parsing library.
    cookie_strings = re.findall(r'[^,;]+(?:;[^,;]+)*', set_cookie_headers)
    
    # Check if the final URL is HTTPS, which is crucial for the 'Secure' flag.
    is_https = urlparse(final_url).scheme == 'https'

    all_cookies_secure = True
    all_cookies_httponly = True
    all_cookies_samesite = True

    for cookie_str in cookie_strings:
        # Extract cookie name for more specific reporting
        cookie_name_match = re.match(r'([^=]+)=', cookie_str)
        cookie_name = cookie_name_match.group(1).strip() if cookie_name_match else "Unknown_Cookie"

        is_secure = re.search(r';\s*secure', cookie_str, re.IGNORECASE) is not None
        is_httponly = re.search(r';\s*httponly', cookie_str, re.IGNORECASE) is not None
        samesite_match = re.search(r';\s*samesite=(lax|strict|none)', cookie_str, re.IGNORECASE)
        
        # --- HttpOnly Flag Check ---
        if not is_httponly:
            all_cookies_httponly = False
            findings.append(
                SecurityFinding(
                    f"Set-Cookie (HttpOnly) for '{cookie_name}'",
                    "MISCONFIGURED",
                    Severity.HIGH,
                    f"Cookie '{cookie_name}' is missing the 'HttpOnly' flag.",
                    cookie_str,
                    "Add the 'HttpOnly' flag to prevent client-side scripts (e.g., JavaScript) from accessing "
                    "the cookie, significantly mitigating XSS attacks where cookies might contain session tokens."
                )
            )

        # --- Secure Flag Check ---
        if is_https and not is_secure:
            all_cookies_secure = False
            findings.append(
                SecurityFinding(
                    f"Set-Cookie (Secure) for '{cookie_name}'",
                    "MISCONFIGURED",
                    Severity.HIGH,
                    f"Cookie '{cookie_name}' is missing the 'Secure' flag, despite being served over HTTPS.",
                    cookie_str,
                    "Add the 'Secure' flag to ensure the cookie is only sent over encrypted HTTPS connections, "
                    "protecting it from interception by man-in-the-middle attacks."
                )
            )
        elif not is_https and not is_secure:
            # If the site itself is not HTTPS, the Secure flag is not applicable,
            # but the primary recommendation is to use HTTPS.
            findings.append(
                SecurityFinding(
                    f"Set-Cookie (Secure) for '{cookie_name}'",
                    "INFO",
                    Severity.INFO,
                    f"Cookie '{cookie_name}' is missing the 'Secure' flag. The site itself is served over HTTP.",
                    cookie_str,
                    "Consider migrating your entire site to HTTPS. Once on HTTPS, ensure all cookies "
                    "are set with the 'Secure' flag."
                )
            )

        # --- SameSite Flag Check ---
        if not samesite_match:
            all_cookies_samesite = False
            findings.append(
                SecurityFinding(
                    f"Set-Cookie (SameSite) for '{cookie_name}'",
                    "MISCONFIGURED",
                    Severity.MEDIUM,
                    f"Cookie '{cookie_name}' is missing the 'SameSite' attribute.",
                    cookie_str,
                    "Add the 'SameSite=Lax' or 'SameSite=Strict' attribute to mitigate Cross-Site Request Forgery (CSRF) attacks. "
                    "If cross-site cookie usage is an absolute requirement, use 'SameSite=None' but ONLY with the 'Secure' flag."
                )
            )
        else:
            samesite_value = samesite_match.group(1).lower()
            if samesite_value == 'none' and not is_secure:
                all_cookies_samesite = False
                findings.append(
                    SecurityFinding(
                        f"Set-Cookie (SameSite=None) for '{cookie_name}'",
                        "MISCONFIGURED",
                        Severity.HIGH,
                        f"Cookie '{cookie_name}' uses 'SameSite=None' without the 'Secure' flag.",
                        cookie_str,
                        "Cookies with 'SameSite=None' MUST also include the 'Secure' flag. "
                        "This configuration is highly vulnerable to interception over HTTP."
                    )
                )

    # Add a general finding if all cookies checked appear to be configured correctly
    if all_cookies_secure and all_cookies_httponly and all_cookies_samesite and set_cookie_headers:
        findings.insert(0, SecurityFinding( # Insert at beginning for summary
            "Set-Cookie (Overall)",
            "PRESENT_OK",
            Severity.GOOD,
            "All 'Set-Cookie' headers appear to have appropriate HttpOnly, Secure (where applicable), and SameSite flags.",
            set_cookie_headers,
            "Good practice maintained for cookie security. Continue to review cookie settings."
        ))

    return findings


def analyze_content_security_policy(headers):
    """
    Analyzes the 'Content-Security-Policy' (CSP) header for presence and common misconfigurations.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list containing one SecurityFinding object for CSP.
    """
    csp = headers.get('Content-Security-Policy')
    findings = []

    if not csp:
        findings.append(
            SecurityFinding(
                "Content-Security-Policy",
                "MISSING",
                Severity.CRITICAL,
                "The 'Content-Security-Policy' header is missing. This leaves the site highly vulnerable to "
                "Cross-Site Scripting (XSS), data injection, and other client-side attacks.",
                None,
                "Implement a strong CSP to mitigate XSS and content injection. Start with a strict policy like "
                "`default-src 'self';` and gradually add necessary sources, avoiding `unsafe-inline` and `unsafe-eval`."
            )
        )
        return findings
    
    details = []
    recommendations = []
    
    # Check for report-uri or report-to directives (important for monitoring CSP violations)
    if not re.search(r'(report-uri|report-to)\s+', csp, re.IGNORECASE):
        details.append("Missing CSP reporting directives (report-uri or report-to).")
        recommendations.append("Add `report-uri` or `report-to` to collect violation reports and monitor CSP effectiveness in production.")

    # Check for 'unsafe-inline' or 'unsafe-eval' in script-src or default-src, which significantly weaken CSP.
    if re.search(r'(script-src|default-src)\s+[^;]*(\'unsafe-inline\'|\'unsafe-eval\')', csp, re.IGNORECASE):
        details.append("CSP contains 'unsafe-inline' or 'unsafe-eval' in `script-src` or `default-src`, which significantly weakens XSS protection.")
        recommendations.append("Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for inline scripts/styles, or refactor to use external scripts.")
        
    # Check for `object-src 'none'` or `'self'` (to restrict plugins like Flash)
    if not re.search(r'object-src\s+[^;]*(\'none\'|\'self\')', csp, re.IGNORECASE):
        details.append("CSP does not restrict `object-src` or allows arbitrary sources for plugins (e.g., Flash, Java applets).")
        recommendations.append("Set `object-src 'none'` or `object-src 'self'` to prevent injection of malicious plugins.")

    # Check for `base-uri 'self'` or `'none'` (to prevent base tag injection attacks)
    if not re.search(r'base-uri\s+[^;]*(\'self\'|\'none\')', csp, re.IGNORECASE):
        details.append("CSP does not restrict `base-uri`.")
        recommendations.append("Set `base-uri 'self'` or `base-uri 'none'` to prevent attackers from injecting malicious `<base>` tags that can redirect relative URLs.")

    # Check for `frame-ancestors` (to control framing behavior, similar to X-Frame-Options)
    if not re.search(r'frame-ancestors\s+', csp, re.IGNORECASE):
        details.append("CSP is missing the `frame-ancestors` directive.")
        recommendations.append("Add `frame-ancestors 'none'` or `frame-ancestors 'self'` to control where your content can be embedded in iframes, preventing clickjacking.")
    elif re.search(r'frame-ancestors\s+[^;]*(\*)', csp, re.IGNORECASE):
        details.append("CSP `frame-ancestors` directive allows framing from any origin (`*`), which is insecure.")
        recommendations.append("Restrict `frame-ancestors` to `'self'` or specific trusted domains to prevent clickjacking.")

    # Check for lack of 'upgrade-insecure-requests' on HTTP sites for forced HTTPS
    parsed_url = urlparse(sys.argv[1]) # Use initial requested URL to determine scheme
    if parsed_url.scheme == 'http' and 'upgrade-insecure-requests' not in csp.lower():
        details.append("Site is HTTP but CSP is missing 'upgrade-insecure-requests'.")
        recommendations.append("If migrating to HTTPS, add `upgrade-insecure-requests` to automatically rewrite HTTP requests to HTTPS, preventing mixed content issues.")


    if details:
        findings.append(
            SecurityFinding(
                "Content-Security-Policy",
                "MISCONFIGURED",
                Severity.HIGH,
                f"CSP is present but has potential weaknesses: {'; '.join(details)}",
                csp,
                f"Consider implementing the following to strengthen your CSP: {'; '.join(recommendations)}"
            )
        )
    else:
        findings.append(
            SecurityFinding(
                "Content-Security-Policy",
                "PRESENT_OK",
                Severity.GOOD,
                "Content-Security-Policy is present and appears to be well-configured with no obvious weaknesses.",
                csp,
                "Excellent! Regularly review your CSP for evolving threats and application changes."
            )
        )
    return findings


def analyze_strict_transport_security(headers, final_url):
    """
    Analyzes the 'Strict-Transport-Security' (HSTS) header.
    Args:
        headers (dict): Normalized HTTP response headers.
        final_url (str): The final URL after redirects, used to check if HTTPS is in use.
    Returns:
        list: A list containing one SecurityFinding object for HSTS.
    """
    hsts = headers.get('Strict-Transport-Security')
    
    # HSTS header is only effective and honored by browsers when served over HTTPS.
    if urlparse(final_url).scheme != 'https':
        if hsts:
            return [
                SecurityFinding(
                    "Strict-Transport-Security (HSTS)",
                    "PRESENT_BUT_INEFFECTIVE",
                    Severity.INFO,
                    "HSTS header is present but served over HTTP. HSTS is only honored by browsers when received via HTTPS.",
                    hsts,
                    "Ensure your site enforces HTTPS for all traffic. The HSTS header should ONLY be set on HTTPS responses "
                    "to prevent it from being stripped by attackers on initial HTTP connections."
                )
            ]
        else:
            return [
                SecurityFinding(
                    "Strict-Transport-Security (HSTS)",
                    "MISSING",
                    Severity.HIGH,
                    "The site is not using HTTPS, or the HSTS header is missing on HTTPS responses. "
                    "This leaves users vulnerable to SSL stripping attacks and allows protocol downgrade.",
                    None,
                    "Migrate your site entirely to HTTPS and implement the HSTS header with a sufficient `max-age`, "
                    "`includeSubDomains`, and consider `preload` for optimal security."
                )
            ]

    # If the request was served over HTTPS, proceed with HSTS specific checks.
    if not hsts:
        return [
            SecurityFinding(
                "Strict-Transport-Security (HSTS)",
                "MISSING",
                Severity.HIGH,
                "The 'Strict-Transport-Security' (HSTS) header is missing, "
                "leaving the site vulnerable to SSL stripping attacks (e.g., downgrade to HTTP) and cookie hijacking.",
                None,
                "Implement HSTS with a long `max-age` (e.g., 31536000 seconds for one year) and `includeSubDomains`. "
                "Consider the `preload` directive after stable implementation."
            )
        ]

    details = []
    recommendations = []
    
    # Check max-age directive: should be sufficiently long (e.g., 1 year or more).
    max_age_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
    if not max_age_match:
        details.append("Missing 'max-age' directive.")
        recommendations.append("Ensure 'max-age' is present and set to a long duration (e.g., 31536000 seconds for one year) "
                               "to maximize the period browsers remember to connect via HTTPS.")
    else:
        max_age = int(max_age_match.group(1))
        # OWASP recommends a minimum of one year (31536000 seconds) for production sites.
        if max_age < 31536000: 
            details.append(f" 'max-age' ({max_age} seconds) is too short.")
            recommendations.append("Increase 'max-age' to at least 31536000 seconds (1 year) for better security against transient attacks.")
        else:
            details.append(f" 'max-age' ({max_age} seconds) is good.")

    # Check includeSubDomains directive: important for protecting all subdomains.
    if 'includesubdomains' not in hsts.lower():
        details.append("Missing 'includeSubDomains' directive.")
        recommendations.append("Add 'includeSubDomains' to protect all subdomains under the current domain, preventing attacks on subdomains.")

    # Check preload directive: for inclusion in browser's HSTS preload list.
    if 'preload' not in hsts.lower():
        details.append("Missing 'preload' directive.")
        recommendations.append("Consider adding 'preload' after stable HSTS deployment and submitting your domain to the HSTS preload list "
                               "to ensure browsers never make an HTTP connection to your site.")

    if details:
        # Determine severity based on the most critical missing directive.
        status = "MISCONFIGURED"
        severity = Severity.HIGH if any(d in details for d in ["max-age", "includeSubDomains"]) else Severity.MEDIUM
        return [
            SecurityFinding(
                "Strict-Transport-Security (HSTS)",
                status,
                severity,
                f"HSTS is present but has potential weaknesses: {'; '.join(details)}",
                hsts,
                f"Consider implementing the following to strengthen your HSTS policy: {'; '.join(recommendations)}"
            )
        ]
    else:
        return [
            SecurityFinding(
                "Strict-Transport-Security (HSTS)",
                "PRESENT_OK",
                Severity.GOOD,
                "Strict-Transport-Security (HSTS) header is present and well-configured.",
                hsts,
                "Excellent! Your site effectively protects against protocol downgrade and related attacks."
            )
        ]


def analyze_x_frame_options(headers):
    """
    Analyzes the 'X-Frame-Options' header to prevent Clickjacking.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list containing one SecurityFinding object for X-Frame-Options.
    """
    xfo = headers.get('X-Frame-Options')

    if not xfo:
        return [
            SecurityFinding(
                "X-Frame-Options",
                "MISSING",
                Severity.MEDIUM,
                "The 'X-Frame-Options' header is missing, making the site vulnerable to Clickjacking attacks.",
                None,
                "Implement 'X-Frame-Options' with 'DENY' or 'SAMEORIGIN' to prevent your site content "
                "from being embedded in malicious iframes, frames, or object tags."
            )
        ]
    
    xfo_lower = xfo.lower()
    if 'deny' in xfo_lower:
        return [
            SecurityFinding(
                "X-Frame-Options",
                "PRESENT_OK",
                Severity.GOOD,
                "X-Frame-Options is set to 'DENY', which is the most secure option against Clickjacking.",
                xfo,
                "Excellent! This effectively prevents framing of your content by any other site."
            )
        ]
    elif 'sameorigin' in xfo_lower:
        return [
            SecurityFinding(
                "X-Frame-Options",
                "PRESENT_OK",
                Severity.GOOD,
                "X-Frame-Options is set to 'SAMEORIGIN', allowing framing only from the same origin.",
                xfo,
                "Good. This provides robust protection against Clickjacking for most scenarios. Consider 'DENY' "
                "if your site is never intended to be framed, even by itself."
            )
        ]
    elif 'allow-from' in xfo_lower:
        # ALLOW-FROM is deprecated and not supported by modern browsers.
        # Content-Security-Policy's `frame-ancestors` directive is the modern replacement.
        return [
            SecurityFinding(
                "X-Frame-Options",
                "MISCONFIGURED",
                Severity.LOW, # Lower severity as modern browsers might ignore it in favor of CSP
                "X-Frame-Options is set to 'ALLOW-FROM', which is deprecated and inconsistently supported "
                "across browsers. Its effectiveness is limited.",
                xfo,
                "Consider using 'DENY' or 'SAMEORIGIN'. For more granular control over framing, use the "
                "`frame-ancestors` directive within your Content-Security-Policy."
            )
        ]
    else:
        return [
            SecurityFinding(
                "X-Frame-Options",
                "MISCONFIGURED",
                Severity.HIGH,
                f"X-Frame-Options is present but has an unrecognized or insecure value: {xfo}",
                xfo,
                "Ensure X-Frame-Options is set to 'DENY' or 'SAMEORIGIN'. Other values are either invalid or weak."
            )
        ]


def analyze_x_content_type_options(headers):
    """
    Analyzes the 'X-Content-Type-Options' header to prevent MIME-sniffing.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list containing one SecurityFinding object for X-Content-Type-Options.
    """
    xcto = headers.get('X-Content-Type-Options')

    if not xcto:
        return [
            SecurityFinding(
                "X-Content-Type-Options",
                "MISSING",
                Severity.MEDIUM,
                "The 'X-Content-Type-Options' header is missing. This can lead to MIME-sniffing vulnerabilities, "
                "where browsers try to guess the content type and might execute malicious scripts.",
                None,
                "Implement 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing and "
                "force them to use the declared `Content-Type` header, enhancing security."
            )
        ]
    
    if 'nosniff' in xcto.lower():
        return [
            SecurityFinding(
                "X-Content-Type-Options",
                "PRESENT_OK",
                Severity.GOOD,
                "X-Content-Type-Options is set to 'nosniff', which is the recommended secure configuration.",
                xcto,
                "Excellent! This helps prevent MIME-sniffing attacks, ensuring browsers interpret content as intended."
            )
        ]
    else:
        return [
            SecurityFinding(
                "X-Content-Type-Options",
                "MISCONFIGURED",
                Severity.HIGH,
                f"X-Content-Type-Options is present but has an unrecognized or insecure value: {xcto}",
                xcto,
                "Ensure X-Content-Type-Options is set to 'nosniff'. Any other value is not effective for security."
            )
        ]


def analyze_x_xss_protection(headers):
    """
    Analyzes the 'X-XSS-Protection' header.
    Note: This header is largely obsolete as modern browsers' built-in XSS filters and
    a robust Content-Security-Policy offer better and more consistent protection.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list containing one SecurityFinding object for X-XSS-Protection.
    """
    xxp = headers.get('X-XSS-Protection')

    if not xxp:
        return [
            SecurityFinding(
                "X-XSS-Protection",
                "MISSING",
                Severity.LOW, # Lower severity due to modern browser improvements and CSP
                "The 'X-XSS-Protection' header is missing. While largely superseded by CSP, it still provides "
                "some protection in older browsers or those without advanced XSS filtering.",
                None,
                "Consider adding 'X-XSS-Protection: 1; mode=block'. However, prioritize and focus on "
                "implementing a robust Content-Security-Policy, as it offers superior XSS protection."
            )
        ]

    xxp_lower = xxp.lower()
    if '1; mode=block' in xxp_lower:
        return [
            SecurityFinding(
                "X-XSS-Protection",
                "PRESENT_OK",
                Severity.GOOD,
                "X-XSS-Protection is set to '1; mode=block', which is the recommended secure configuration for this header.",
                xxp,
                "Good. This activates the browser's built-in XSS filter. Ensure a strong CSP is also in place as the primary defense."
            )
        ]
    elif '1' in xxp_lower and 'mode=block' not in xxp_lower:
        return [
            SecurityFinding(
                "X-XSS-Protection",
                "MISCONFIGURED",
                Severity.LOW,
                "X-XSS-Protection is enabled ('1') but 'mode=block' is missing.",
                xxp,
                "Change to 'X-XSS-Protection: 1; mode=block' to actively prevent rendering pages with detected XSS attacks. "
                "Without `mode=block`, the browser might attempt to sanitize, which can be bypassed."
            )
        ]
    elif '0' in xxp_lower:
        return [
            SecurityFinding(
                "X-XSS-Protection",
                "MISCONFIGURED",
                Severity.MEDIUM,
                "X-XSS-Protection is explicitly disabled ('0').",
                xxp,
                "Consider removing this header entirely or setting it to '1; mode=block' if you intend to rely on it. "
                "If you have a strong CSP, this header's absence or disabling might be acceptable, but it's generally best to avoid explicit disabling."
            )
        ]
    else:
        return [
            SecurityFinding(
                "X-XSS-Protection",
                "MISCONFIGURED",
                Severity.LOW,
                f"X-XSS-Protection is present but has an unrecognized value: {xxp}",
                xxp,
                "Ensure X-XSS-Protection is set to '1; mode=block' or rely solely on a strong Content-Security-Policy."
            )
        ]


def analyze_referrer_policy(headers):
    """
    Analyzes the 'Referrer-Policy' header to control referrer information leakage.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list containing one SecurityFinding object for Referrer-Policy.
    """
    rp = headers.get('Referrer-Policy')

    if not rp:
        return [
            SecurityFinding(
                "Referrer-Policy",
                "MISSING",
                Severity.LOW,
                "The 'Referrer-Policy' header is missing. This might lead to unintended leakage of sensitive "
                "information (e.g., full URL paths, session IDs in URLs) in referrer headers to third-party sites.",
                None,
                "Implement a 'Referrer-Policy' (e.g., 'no-referrer', 'same-origin', or 'strict-origin-when-cross-origin') "
                "to control what referrer information is sent with requests, enhancing user privacy."
            )
        ]

    rp_lower = rp.lower()
    
    # Recommended policies that balance privacy and functionality
    # 'no-referrer': Never send the Referer header.
    # 'same-origin': Send Referer for same-origin requests only.
    # 'strict-origin-when-cross-origin': Send only the origin for cross-origin requests, full URL for same-origin.
    if 'no-referrer' in rp_lower or 'same-origin' in rp_lower or 'strict-origin-when-cross-origin' in rp_lower:
        return [
            SecurityFinding(
                "Referrer-Policy",
                "PRESENT_OK",
                Severity.GOOD,
                f"Referrer-Policy is set to '{rp}', which is a secure and privacy-preserving configuration.",
                rp,
                "Excellent! You are controlling referrer information effectively, minimizing data leakage."
            )
        ]
    elif 'unsafe-url' in rp_lower:
        return [
            SecurityFinding(
                "Referrer-Policy",
                "MISCONFIGURED",
                Severity.MEDIUM,
                "Referrer-Policy is set to 'unsafe-url', which sends the full URL with origin and path "
                "for all requests, potentially leaking sensitive information, even from HTTPS to HTTP.",
                rp,
                "Change to a more restrictive policy like 'no-referrer', 'same-origin', or 'strict-origin-when-cross-origin' "
                "to protect user privacy and sensitive data."
            )
        ]
    else:
        # Other valid policies like 'origin', 'origin-when-cross-origin', 'no-referrer-when-downgrade'
        # are less ideal from a privacy perspective compared to the recommended ones.
        return [
            SecurityFinding(
                "Referrer-Policy",
                "PRESENT_WEAK",
                Severity.LOW,
                f"Referrer-Policy is present but set to '{rp}'. Consider a more privacy-preserving policy.",
                rp,
                "Review the impact of your current policy. Consider using 'no-referrer', 'same-origin', "
                "or 'strict-origin-when-cross-origin' for better protection against referrer leakage."
            )
        ]


def analyze_permissions_policy(headers):
    """
    Analyzes the 'Permissions-Policy' (formerly 'Feature-Policy') header.
    This header allows a site to control browser features and APIs available to itself and embedded content.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list containing one SecurityFinding object for Permissions-Policy.
    """
    pp = headers.get('Permissions-Policy')

    if not pp:
        return [
            SecurityFinding(
                "Permissions-Policy",
                "MISSING",
                Severity.INFO,
                "The 'Permissions-Policy' header is missing. This header allows control over browser features "
                "and APIs, enhancing security and privacy by explicitly enabling/disabling capabilities.",
                None,
                "Consider implementing 'Permissions-Policy' to restrict access to sensitive browser features "
                "(e.g., camera, microphone, geolocation) by default (`self`) or disable them entirely (`()`), "
                "especially if your application doesn't require them."
            )
        ]
    
    # A very secure policy would restrict many features to 'self' or '()'.
    details = []
    # Check for common sensitive features that should often be restricted.
    # The syntax is `feature=(self "https://example.com")` or `feature=()`.
    # We are looking for an explicit restriction.
    if not re.search(r'camera=\(\)', pp, re.IGNORECASE) and not re.search(r'camera=self', pp, re.IGNORECASE) and not re.search(r'camera=\("[^"]*"\)', pp, re.IGNORECASE):
        details.append("Camera access not explicitly restricted or allowed to all.")
    if not re.search(r'microphone=\(\)', pp, re.IGNORECASE) and not re.search(r'microphone=self', pp, re.IGNORECASE) and not re.search(r'microphone=\("[^"]*"\)', pp, re.IGNORECASE):
        details.append("Microphone access not explicitly restricted or allowed to all.")
    if not re.search(r'geolocation=\(\)', pp, re.IGNORECASE) and not re.search(r'geolocation=self', pp, re.IGNORECASE) and not re.search(r'geolocation=\("[^"]*"\)', pp, re.IGNORECASE):
        details.append("Geolocation access not explicitly restricted or allowed to all.")
    if not re.search(r'fullscreen=\(\)', pp, re.IGNORECASE) and not re.search(r'fullscreen=self', pp, re.IGNORECASE) and not re.search(r'fullscreen=\("[^"]*"\)', pp, re.IGNORECASE):
        details.append("Fullscreen access not explicitly restricted or allowed to all.")
    if not re.search(r'autoplay=\(\)', pp, re.IGNORECASE) and not re.search(r'autoplay=self', pp, re.IGNORECASE) and not re.search(r'autoplay=\("[^"]*"\)', pp, re.IGNORECASE):
        details.append("Autoplay not explicitly restricted or allowed to all.")
    
    if details:
        return [
            SecurityFinding(
                "Permissions-Policy",
                "PRESENT_WEAK",
                Severity.LOW,
                f"Permissions-Policy is present but could be more restrictive regarding certain features: {'; '.join(details)}",
                pp,
                "Consider explicitly disabling (`()`) or restricting (`self` or specific origins) access to "
                "sensitive browser features like camera, microphone, geolocation, and autoplay if they are not needed by your application or its embedded content."
            )
        ]
    else:
        return [
            SecurityFinding(
                "Permissions-Policy",
                "PRESENT_OK",
                Severity.GOOD,
                "Permissions-Policy header is present and appears to be configured well, restricting sensitive features.",
                pp,
                "Excellent! This helps control access to powerful browser features and enhances security/privacy."
            )
        ]


def analyze_expect_ct(headers):
    """
    Analyzes the 'Expect-CT' header for Certificate Transparency enforcement.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list containing one SecurityFinding object for Expect-CT.
    """
    ect = headers.get('Expect-CT')

    if not ect:
        return [
            SecurityFinding(
                "Expect-CT",
                "MISSING",
                Severity.INFO,
                "The 'Expect-CT' header is missing. This header helps mitigate misissued certificates "
                "by enforcing Certificate Transparency, ensuring all certificates are publicly logged.",
                None,
                "Consider implementing 'Expect-CT' to ensure all certificates for your domain are publicly logged. "
                "Start with `Expect-CT: max-age=<seconds>, report-uri=\"<report_endpoint>\"` in report-only mode, then switch to `enforce`."
            )
        ]

    details = []
    recommendations = []

    # Check for 'enforce' directive (activates blocking behavior)
    if 'enforce' not in ect.lower():
        details.append("Missing 'enforce' directive.")
        recommendations.append("Add 'enforce' to actively block connections that present non-compliant certificates (after thorough testing). "
                               "Alternatively, keep in report-only mode if still monitoring.")

    # Check max-age directive (how long the policy is cached by the browser)
    max_age_match = re.search(r'max-age=(\d+)', ect, re.IGNORECASE)
    if not max_age_match:
        details.append("Missing 'max-age' directive.")
        recommendations.append("Ensure 'max-age' is present and set to a suitable duration (e.g., 30 days or more).")
    else:
        max_age = int(max_age_match.group(1))
        # A common recommendation is at least 30 days (86400 * 30 seconds).
        if max_age < 86400 * 30: 
            details.append(f" 'max-age' ({max_age} seconds) is relatively short.")
            recommendations.append("Consider increasing 'max-age' for better long-term protection, ensuring the policy remains active longer.")
    
    # Check report-uri directive (where to send violation reports)
    if 'report-uri' not in ect.lower():
        details.append("Missing 'report-uri' directive.")
        recommendations.append("Add 'report-uri' to receive reports on CT policy violations, which is crucial for monitoring and debugging.")

    if details:
        return [
            SecurityFinding(
                "Expect-CT",
                "MISCONFIGURED",
                Severity.LOW,
                f"Expect-CT is present but could be strengthened: {'; '.join(details)}",
                ect,
                f"Consider implementing the following: {'; '.join(recommendations)}"
            )
        ]
    else:
        return [
            SecurityFinding(
                "Expect-CT",
                "PRESENT_OK",
                Severity.GOOD,
                "Expect-CT header is present and well-configured, effectively enforcing Certificate Transparency.",
                ect,
                "Excellent! This helps protect against misissued or maliciously obtained certificates."
            )
        ]


def analyze_server_information_leakage(headers):
    """
    Analyzes headers that might leak server software, version, or underlying technology information.
    Such information can aid attackers in identifying known vulnerabilities.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list of SecurityFinding objects for information leakage.
    """
    findings = []
    
    # --- Server header analysis ---
    server_header = headers.get('Server')
    if server_header:
        # Check for specific versions, common server software names (Apache, Nginx, IIS), or cloud platforms (Cloudflare).
        # Presence of version numbers (e.g., 1.2.3) is particularly problematic.
        if re.search(r'\d+(\.\d+){1,}|apache|nginx|iis|microsoft-iis|cloudflare|gws|aws', server_header, re.IGNORECASE):
            severity = Severity.LOW if re.search(r'\d+(\.\d+){1,}', server_header) else Severity.INFO
            findings.append(
                SecurityFinding(
                    "Server",
                    "PRESENT_WEAK",
                    severity,
                    f"The 'Server' header is present and reveals server software/version information: {server_header}",
                    server_header,
                    "Remove or generalize the 'Server' header to prevent attackers from easily identifying "
                    "known vulnerabilities related to specific server software and versions. Obfuscation (e.g., 'Web Server') "
                    "or complete removal are good practices."
                )
            )
        else:
             findings.append(
                SecurityFinding(
                    "Server",
                    "PRESENT_OK",
                    Severity.INFO,
                    f"The 'Server' header is present but appears to be generic or obfuscated: {server_header}",
                    server_header,
                    "Good practice. However, consider removing it entirely if it serves no functional purpose, "
                    "as any information, however generic, can potentially be useful to an attacker."
                )
            )
    else:
        findings.append(
            SecurityFinding(
                "Server",
                "MISSING",
                Severity.GOOD,
                "The 'Server' header is not present, which is good security practice (information hiding).",
                None,
                "N/A - This is an excellent security posture."
            )
        )

    # --- X-Powered-By header analysis ---
    x_powered_by = headers.get('X-Powered-By')
    if x_powered_by:
        findings.append(
            SecurityFinding(
                "X-Powered-By",
                "PRESENT_WEAK",
                Severity.LOW,
                f"The 'X-Powered-By' header is present and reveals technology stack information: {x_powered_by}",
                x_powered_by,
                "Remove the 'X-Powered-By' header to prevent attackers from easily identifying "
                "the technologies (e.g., ASP.NET, PHP, Express) used by the application, which could lead to targeted attacks."
            )
        )
    else:
        findings.append(
            SecurityFinding(
                "X-Powered-By",
                "MISSING",
                Severity.GOOD,
                "The 'X-Powered-By' header is not present, which is good security practice (information hiding).",
                None,
                "N/A - This is an excellent security posture."
            )
        )

    # --- X-AspNet-Version and X-AspNetMvc-Version headers ---
    # These are specific to ASP.NET applications and can reveal sensitive version info.
    x_aspnet_version = headers.get('X-AspNet-Version')
    if x_aspnet_version:
        findings.append(
            SecurityFinding(
                "X-AspNet-Version",
                "PRESENT_WEAK",
                Severity.LOW,
                f"The 'X-AspNet-Version' header is present and reveals ASP.NET version: {x_aspnet_version}",
                x_aspnet_version,
                "Remove this header to prevent attackers from targeting known vulnerabilities in specific ASP.NET versions. "
                "This can typically be done in the web.config file (`enableVersionHeader=false`)."
            )
        )
    
    x_aspnetmvc_version = headers.get('X-AspNetMvc-Version')
    if x_aspnetmvc_version:
        findings.append(
            SecurityFinding(
                "X-AspNetMvc-Version",
                "PRESENT_WEAK",
                Severity.LOW,
                f"The 'X-AspNetMvc-Version' header is present and reveals ASP.NET MVC version: {x_aspnetmvc_version}",
                x_aspnetmvc_version,
                "Remove this header to prevent attackers from targeting known vulnerabilities in specific ASP.NET MVC versions. "
                "This can typically be disabled in Global.asax or by removing the `X-AspNetMvc-Version` header in IIS configuration."
            )
        )
    
    # --- Other potential information leakage headers ---
    # X-Generator (e.g., for CMS like WordPress, Joomla)
    x_generator = headers.get('X-Generator')
    if x_generator:
        findings.append(
            SecurityFinding(
                "X-Generator",
                "PRESENT_WEAK",
                Severity.LOW,
                f"The 'X-Generator' header is present and reveals application/CMS information: {x_generator}",
                x_generator,
                "Remove this header to prevent attackers from easily identifying the CMS or application generator "
                "and targeting known vulnerabilities associated with that platform."
            )
        )

    return findings

def analyze_cache_control(headers):
    """
    Analyzes the 'Cache-Control' header for security implications, particularly preventing
    sensitive data from being cached by shared (proxy) caches or stored persistently.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list containing one SecurityFinding object for Cache-Control.
    """
    cache_control = headers.get('Cache-Control')

    if not cache_control:
        return [
            SecurityFinding(
                "Cache-Control",
                "MISSING",
                Severity.INFO,
                "The 'Cache-Control' header is missing. This might lead to unintended caching behavior, "
                "potentially exposing sensitive data through shared caches or serving stale content.",
                None,
                "Implement 'Cache-Control' directives appropriate for your content. For sensitive content, "
                "use 'no-store, no-cache, must-revalidate' to prevent any form of caching. For static assets, "
                "use appropriate `max-age` values."
            )
        ]
    
    cache_control_lower = cache_control.lower()
    details = []
    recommendations = []

    # Check for directives that prevent caching of sensitive information by shared caches.
    # 'no-store': Do not store any part of the request or response in any cache.
    # 'private': Allow caching by private caches (e.g., browser cache) but not by shared caches.
    if 'no-store' not in cache_control_lower and 'private' not in cache_control_lower:
        details.append("Missing 'no-store' or 'private' directives. Content might be cached by shared (proxy) caches.")
        recommendations.append("For sensitive or user-specific content, include 'no-store' or 'private' to prevent caching by intermediaries.")

    # Check for directives that ensure content is always revalidated or not cached.
    # 'no-cache': Cache must revalidate with the origin server before reuse.
    # 'must-revalidate': If cache is stale, it must revalidate or not use the entry.
    if 'no-cache' not in cache_control_lower and 'must-revalidate' not in cache_control_lower and 'no-store' not in cache_control_lower:
        details.append("Missing 'no-cache' or 'must-revalidate' (or 'no-store'). Stale cached content might be served or revalidation not enforced.")
        recommendations.append("For content that needs fresh validation on each access, include 'no-cache' or 'must-revalidate'.")

    # If 'public' is explicitly set on sensitive content, it's a concern.
    # It allows any cache (private or shared) to store the response.
    if 'public' in cache_control_lower and ('no-store' not in cache_control_lower and 'private' not in cache_control_lower):
        details.append("The 'public' directive is present. Ensure this is appropriate for the content, especially if sensitive.")
        recommendations.append("Avoid 'public' on responses containing sensitive user data. Use 'private' or 'no-store' instead.")

    if details:
        # If 'no-store' is present, it overrides many other directives for security, so severity can be lower.
        severity = Severity.MEDIUM if 'no-store' not in cache_control_lower else Severity.LOW
        return [
            SecurityFinding(
                "Cache-Control",
                "MISCONFIGURED",
                severity,
                f"Cache-Control is present but could be improved for security/privacy: {'; '.join(details)}",
                cache_control,
                f"Consider implementing: {'; '.join(recommendations)}"
            )
        ]
    else:
        return [
            SecurityFinding(
                "Cache-Control",
                "PRESENT_OK",
                Severity.GOOD,
                "Cache-Control header is present and appears to be configured securely or appropriately for the content type.",
                cache_control,
                "Good practice for managing caching and preventing leakage of sensitive data."
            )
        ]

def analyze_pragma_header(headers):
    """
    Analyzes the 'Pragma' header, specifically checking for 'no-cache' for backward compatibility.
    The 'Pragma' header is an HTTP/1.0 header and is largely superseded by 'Cache-Control' in HTTP/1.1+.
    Args:
        headers (dict): Normalized HTTP response headers.
    Returns:
        list: A list containing one SecurityFinding object for Pragma.
    """
    pragma = headers.get('Pragma')

    if not pragma:
        return [
            SecurityFinding(
                "Pragma",
                "MISSING",
                Severity.INFO,
                "The 'Pragma' header is missing. While largely superseded by 'Cache-Control' for HTTP/1.1+, "
                "it can provide backward compatibility for older HTTP/1.0 caches to prevent caching.",
                None,
                "Consider adding 'Pragma: no-cache' for backward compatibility with older caching mechanisms or proxies, "
                "especially if serving sensitive content. Ensure 'Cache-Control' is also robust."
            )
        ]
    
    if 'no-cache' in pragma.lower():
        return [
            SecurityFinding(
                "Pragma",
                "PRESENT_OK",
                Severity.GOOD,
                "Pragma header is set to 'no-cache', providing backward compatibility for preventing caching.",
                pragma,
                "Good for backward compatibility, but ensure 'Cache-Control' is the primary and most robust caching mechanism used."
            )
        ]
    else:
        return [
            SecurityFinding(
                "Pragma",
                "PRESENT_WEAK",
                Severity.LOW,
                f"Pragma header is present but not set to 'no-cache': {pragma}",
                pragma,
                "If sensitive content is served, consider setting 'Pragma: no-cache' to ensure older HTTP/1.0 caches do not store it."
            )
        ]

# --- Main Analysis Logic ---

def perform_security_header_analysis(headers, final_url, status_code):
    """
    Orchestrates the analysis of all relevant security headers by calling individual analysis functions.
    Aggregates all findings into a single list.

    Args:
        headers (dict): Normalized HTTP response headers received from the target URL.
        final_url (str): The final URL after any redirects, used for context (e.g., HTTPS check).
        status_code (int): The HTTP status code of the final response.

    Returns:
        list: A consolidated list of SecurityFinding objects from all header analyses.
    """
    all_findings = []

    # Inform the user if the HTTP status code is not a successful 2xx,
    # as this might affect the expected headers or overall site behavior.
    if not (200 <= status_code < 300):
        all_findings.append(
            SecurityFinding(
                "HTTP Status Code",
                "UNEXPECTED",
                Severity.INFO,
                f"Received HTTP status code {status_code}. Header analysis proceeds, but be aware "
                "this might not reflect a normal, successful page load. Some security headers "
                "might only be present on successful responses.",
                str(status_code),
                "Verify the URL and ensure it returns a 2xx status for intended functionality "
                "if you expect a complete set of security headers for the main page."
            )
        )

    print_section("Analyzing Security Headers")
    
    # List of all analysis functions to be executed.
    # Each function is expected to return a list of SecurityFinding objects.
    # Lambda functions are used to pass additional context like `final_url` if needed.
    analysis_functions = [
        analyze_content_security_policy,
        lambda h: analyze_strict_transport_security(h, final_url), # HSTS needs final_url
        analyze_x_frame_options,
        analyze_x_content_type_options,
        analyze_x_xss_protection,
        analyze_referrer_policy,
        analyze_permissions_policy,
        analyze_expect_ct,
        analyze_server_information_leakage,
        analyze_cache_control,
        analyze_pragma_header,
        lambda h: analyze_cookies_security(h, final_url) # Cookie analysis needs final_url
    ]

    # Iterate through each analysis function and collect its findings.
    for func in analysis_functions:
        try:
            # Call each analysis function and extend the main findings list.
            function_findings = func(headers)
            all_findings.extend(function_findings)
        except Exception as e:
            # Robust error handling: Catch any exceptions during an individual analysis
            # to prevent the entire script from crashing and to report the issue.
            # Attempt to infer the header name from the function name.
            header_name_hint = func.__name__.replace('analyze_', '').replace('_', ' ').title()
            print(f"{Color.FAIL}Warning: An error occurred during analysis of {header_name_hint} headers: {e}{Color.ENDC}")
            all_findings.append(
                SecurityFinding(
                    header_name_hint,
                    "ERROR_DURING_ANALYSIS",
                    Severity.CRITICAL,
                    f"An unexpected error occurred while analyzing this header, potentially affecting report accuracy: {e}",
                    None,
                    "Review the application logs for more details or report this issue to the tool maintainer. "
                    "Ensure the target URL is accessible and the response is well-formed."
                )
            )

    return all_findings


# --- Reporting Functionality ---

def generate_detailed_report(findings, initial_input_url, requested_url, final_url, status_code, raw_headers):
    """
    Generates and prints a comprehensive security report based on the collected findings.
    The report includes a summary, detailed findings, and the raw headers.

    Args:
        findings (list): A list of SecurityFinding objects.
        initial_input_url (str): The URL exactly as provided by the user (e.g., from CLI).
        requested_url (str): The URL actually used for the initial HTTP request (after normalization).
        final_url (str): The final URL after any HTTP redirects.
        status_code (int): The HTTP status code of the final response.
        raw_headers (dict): The raw, normalized headers dictionary from the final response.
    """
    print_title("Automated Security Headers Checker Report", char='#', color=Color.HEADER)
    
    # --- Scan Summary Section ---
    print_section("Scan Summary", color=Color.BOLD)
    print(f"  {Color.BOLD}Initial Input URL:{Color.ENDC} {initial_input_url}")
    print(f"  {Color.BOLD}URL Requested:{Color.ENDC} {requested_url}")
    print(f"  {Color.BOLD}Final URL (after redirects):{Color.ENDC} {final_url}")
    print(f"  {Color.BOLD}HTTP Status Code:{Color.ENDC} {status_code}")
    # You could add `import datetime` and use `datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')` here.
    print(f"  {Color.BOLD}Scan Time:{Color.ENDC} N/A (Feature not implemented for brevity, but easily addable)") 

    # --- Overall Findings Summary Section ---
    # Count findings by their severity level for a quick overview.
    severity_counts = {sev: 0 for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.GOOD, "ERROR_DURING_ANALYSIS"]}
    for finding in findings:
        severity_counts[finding.severity] += 1

    print_section("Overall Findings Summary", color=Color.BOLD)
    print(f"  {Color.FAIL}{Color.BOLD}Critical Findings:{Color.ENDC} {severity_counts[Severity.CRITICAL]}")
    print(f"  {Color.FAIL}{Color.BOLD}High Findings:{Color.ENDC} {severity_counts[Severity.HIGH]}")
    print(f"  {Color.WARNING}{Color.BOLD}Medium Findings:{Color.ENDC} {severity_counts[Severity.MEDIUM]}")
    print(f"  {Color.OKCYAN}{Color.BOLD}Low Findings:{Color.ENDC} {severity_counts[Severity.LOW]}")
    print(f"  {Color.OKBLUE}{Color.BOLD}Informational Findings:{Color.ENDC} {severity_counts[Severity.INFO]}")
    print(f"  {Color.OKGREEN}{Color.BOLD}Good Configurations:{Color.ENDC} {severity_counts[Severity.GOOD]}")
    if severity_counts["ERROR_DURING_ANALYSIS"] > 0:
        print(f"  {Color.FAIL}{Color.BOLD}Errors During Analysis:{Color.ENDC} {severity_counts['ERROR_DURING_ANALYSIS']}")
    print(f"\n  {Color.BOLD}Total Findings Reported:{Color.ENDC} {len(findings)}")

    # --- Detailed Findings Section ---
    print_section("Detailed Findings", color=Color.BOLD)
    if not findings:
        print(f"  {Color.OKGREEN}No specific security header findings to report. "
              f"The site might not be setting relevant headers, or all are well-configured.{Color.ENDC}")
    
    # Sort findings by severity for better readability and prioritization.
    # Critical and High findings appear first.
    severity_order = {
        Severity.CRITICAL: 1,
        "ERROR_DURING_ANALYSIS": 2, # Errors should also be high priority
        Severity.HIGH: 3,
        Severity.MEDIUM: 4,
        Severity.LOW: 5,
        Severity.INFO: 6,
        Severity.GOOD: 7,
    }
    # Use a lambda function for sorting based on the defined severity order.
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))

    for finding in sorted_findings:
        # Print each finding using its __str__ method for detailed, color-coded output.
        print(str(finding))
        print("") # Add an extra line for better spacing between findings.

    # --- Raw Response Headers Section ---
    print_section("Raw Response Headers (Normalized)", color=Color.BOLD)
    if raw_headers:
        # Print all headers received in the response.
        # This can be useful for manual inspection or debugging.
        for header, value in raw_headers.items():
            print(f"  {Color.BOLD}{header}:{Color.ENDC} {value}")
    else:
        print(f"  {Color.WARNING}No headers received or an error occurred during the request.{Color.ENDC}")

    print_title("Report End", char='#', color=Color.HEADER)


# --- Command-line Interface (CLI) Setup ---

def validate_url(url_string):
    """
    Validates and normalizes a URL string provided via the command line.
    Ensures a scheme (http/https) is present; defaults to HTTPS if missing.
    Args:
        url_string (str): The URL string to validate.
    Returns:
        str: The normalized URL string.
    Raises:
        argparse.ArgumentTypeError: If the URL is invalid after normalization attempts.
    """
    parsed_url = urlparse(url_string)
    if not parsed_url.scheme:
        # If no scheme is provided, default to HTTPS as it's best practice
        # and many sites redirect from HTTP to HTTPS anyway.
        normalized_url = "https://" + url_string
        print(f"{Color.WARNING}Warning: No scheme specified in URL. Defaulting to HTTPS: {normalized_url}{Color.ENDC}")
        parsed_url = urlparse(normalized_url)
    
    # Basic validation for netloc (domain part).
    if not parsed_url.netloc:
        raise argparse.ArgumentTypeError(f"Invalid URL: '{url_string}'. Please provide a valid domain (e.g., example.com).")

    # Reconstruct the URL to ensure consistency, stripping redundant parts like query/fragment for header checks.
    # This ensures a clean URL is used for the request.
    return urlunparse(parsed_url._replace(query='', fragment=''))


def main():
    """
    Main function to parse command-line arguments, initiate the header fetching process,
    perform security analysis, and generate the final report.
    """
    parser = argparse.ArgumentParser(
        description=f"{Color.BOLD}{Color.HEADER}Automated Security Headers Checker{Color.ENDC}\n"
                    f"A web security tool designed to analyze HTTP response headers for missing or misconfigured "
                    f"security-related settings. It provides detailed findings and recommendations.",
        formatter_class=argparse.RawTextHelpFormatter # Allows for custom formatting (like newlines) in description.
    )
    parser.add_argument(
        "url",
        type=validate_url,
        help="The target URL to check (e.g., https://example.com or example.com).\n"
             "If no scheme (http:// or https://) is provided, HTTPS will be assumed."
    )
    parser.add_argument(
        "--no-redirects",
        action="store_false",
        dest="allow_redirects",
        help="By default, the checker follows HTTP redirects. Use this flag to disable redirect following "
             "and analyze headers of the initial response only."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Sets the maximum number of seconds to wait for the HTTP request to complete (default: 10 seconds)."
    )

    # Pre-check for the 'requests' library, which is essential for this script.
    try:
        import requests
    except ImportError:
        print(f"{Color.FAIL}Error: The 'requests' library is not installed.{Color.ENDC}")
        print(f"{Color.FAIL}Please install it using: pip install requests{Color.ENDC}")
        sys.exit(1)

    # If no arguments are provided, print the help message and exit.
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Parse the command-line arguments.
    args = parser.parse_args()

    # Store the initially provided URL from sys.argv for reporting purposes.
    initial_input_url = sys.argv[1] 
    target_url_normalized = args.url # This is the validated and normalized URL.

    print_title("Scan Started", char='=', color=Color.OKBLUE)
    print(f"{Color.OKBLUE}  Initial Input URL: {initial_input_url}{Color.ENDC}")
    print(f"{Color.OKBLUE}  URL for Request: {target_url_normalized}{Color.ENDC}")
    print(f"{Color.OKBLUE}  Follow Redirects: {args.allow_redirects}{Color.ENDC}")
    print(f"{Color.OKBLUE}  Request Timeout: {args.timeout} seconds{Color.ENDC}")
    print_separator(color=Color.OKBLUE)

    # Fetch headers from the target URL.
    headers, status_code, final_url, response_obj, error = fetch_url_headers(
        target_url_normalized, 
        allow_redirects=args.allow_redirects, 
        timeout=args.timeout
    )

    # If an error occurred during header fetching, print the error and exit.
    if error:
        print(f"{Color.FAIL}Failed to retrieve headers due to an error. Aborting analysis.{Color.ENDC}")
        sys.exit(1)
    
    # Perform the detailed security analysis on the fetched headers.
    findings = perform_security_header_analysis(headers, final_url, status_code)

    # Generate and print the comprehensive report.
    generate_detailed_report(findings, initial_input_url, target_url_normalized, final_url, status_code, headers)

    print_title("Scan Completed", char='=', color=Color.OKBLUE)

# Ensure the main function is called when the script is executed.
if __name__ == "__main__":
    main()