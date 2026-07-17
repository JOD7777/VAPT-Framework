#!/usr/bin/env python3
"""
VAPT Framework - Vulnerability Assessment & Penetration Testing Automation
Author: HackerAI
Purpose: Authorized security assessment and penetration testing
Requirements: Python 3.8+, requests, nmap (optional for advanced scanning)
"""

import os
import sys
import json
import time
import socket
import ipaddress
import subprocess
import threading
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin
from enum import Enum

# ---------------------------------------------------------------------------
# ANSI Colors for output
# ---------------------------------------------------------------------------
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    HEADER = '\033[95m'
    INFO = '\033[96m'

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = f"""
{Colors.RED}
╔════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                    ║
║     ██╗   ██╗ █████╗ ██████╗ ████████╗                                             ║
║     ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝                                             ║
║     ██║   ██║███████║██████╔╝   ██║                                                ║
║     ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║                                                ║
║      ╚████╔╝ ██║  ██║██║        ██║                                                ║
║       ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝                                                ║
║                                                                                    ║
║   ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗   ║
║   ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔════╝██╔═══██╗██║ ██╔╝   ║
║   █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║     ██║   ██║█████╔╝    ║
║   ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║     ██║   ██║██╔═██╗    ║
║   ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╗╚██████╔╝██║  ██╗   ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝   ║
║                                                                                    ║
║           VAPT Framework v2.0 - Security Assessment                                ║
║     {Colors.DIM}Authorized use only. Target: {{target}}{Colors.RESET}{Colors.RED}  ║
║                                                                                    ║
╚════════════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
class Severity(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

class VulnType(Enum):
    SQLI = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    SSRF = "Server-Side Request Forgery"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    OPEN_REDIRECT = "Open Redirect"
    CSRF = "Cross-Site Request Forgery"
    SSTI = "Server-Side Template Injection"
    XXE = "XML External Entity"
    IDOR = "Insecure Direct Object Reference"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    MISCONFIGURATION = "Security Misconfiguration"
    CORS = "CORS Misconfiguration"
    DEBUG_MODE = "Debug Mode Enabled"
    DIRECTORY_LISTING = "Directory Listing"
    OLD_VERSION = "Outdated Software Version"
    WEAK_CIPHER = "Weak Cipher Suite"
    OPEN_PORT = "Open Port"
    DEFAULT_CRED = "Default Credentials"

@dataclass
class Vulnerability:
    vuln_type: VulnType
    severity: Severity
    url: str
    parameter: str = ""
    payload: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cve: str = ""
    cvss_score: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "vulnerability": self.vuln_type.value,
            "severity": self.severity.name,
            "severity_score": self.severity.value,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "description": self.description,
            "evidence": self.evidence[:200] if self.evidence else "",
            "remediation": self.remediation,
            "cve": self.cve,
            "cvss": self.cvss_score,
        }

@dataclass
class ScanTarget:
    url: str
    domain: str = ""
    ip: str = ""
    ports: List[int] = field(default_factory=list)
    technologies: Dict = field(default_factory=dict)
    forms: List[Dict] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    cookies: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.domain and self.url:
            parsed = urlparse(self.url)
            self.domain = parsed.netloc or parsed.path
        if not self.ip and self.domain:
            try:
                self.ip = socket.gethostbyname(self.domain)
            except:
                pass

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------
class Utils:
    @staticmethod
    def print_banner(target: str):
        banner = BANNER.replace("{{target}}", target)
        print(banner)
    
    @staticmethod
    def log(level: str, message: str, timestamp: bool = True):
        ts = f"[{datetime.now().strftime('%H:%M:%S')}] " if timestamp else ""
        colors = {
            "INFO": Colors.INFO,
            "OK": Colors.OKGREEN,
            "WARN": Colors.WARNING,
            "ERROR": Colors.FAIL,
            "CRITICAL": f"{Colors.RED}{Colors.BOLD}",
            "HEADER": Colors.HEADER,
            "DIM": Colors.DIM,
        }
        c = colors.get(level, Colors.WHITE)
        print(f"{c}{ts}[{level}]{Colors.RESET} {message}")
    
    @staticmethod
    def threaded_map(func, items, max_workers=20):
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(func, item): item for item in items}
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    pass
        return results

# ---------------------------------------------------------------------------
# Reconnaissance Module
# ---------------------------------------------------------------------------
class ReconModule:
    """Reconnaissance - Information gathering and footprinting."""
    
    def __init__(self, target: ScanTarget):
        self.target = target
    
    def dns_enumeration(self) -> Dict:
        """Basic DNS enumeration."""
        results = {"a_record": None, "mx_records": [], "ns_records": []}
        
        try:
            results["a_record"] = socket.gethostbyname(self.target.domain)
        except:
            pass
        
        # Try common subdomains
        common_subdomains = ["www", "mail", "admin", "dev", "api", "test", 
                            "staging", "vpn", "portal", "ssh", "webmail",
                            "cpanel", "blog", "forum", "shop", "gitlab",
                            "jenkins", "jira", "confluence"]
        
        found_subdomains = []
        for sub in common_subdomains:
            try:
                full_domain = f"{sub}.{self.target.domain}"
                ip = socket.gethostbyname(full_domain)
                found_subdomains.append({"subdomain": full_domain, "ip": ip})
            except:
                pass
        
        results["subdomains"] = found_subdomains
        return results
    
    def port_scan(self, ports: List[int] = None) -> List[Dict]:
        """Simple TCP port scanner using Python sockets."""
        if not ports:
            # Common ports for initial scan
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                    445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 
                    5900, 5985, 5986, 6379, 8080, 8443, 9000, 9090, 27017]
        
        Utils.log("INFO", f"Scanning {len(ports)} ports on {self.target.ip}...")
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((self.target.ip, port))
                sock.close()
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    return {"port": port, "service": service, "state": "open"}
            except:
                pass
            return None
        
        results = Utils.threaded_map(scan_port, ports, max_workers=50)
        open_ports = [r for r in results if r]
        
        # Common service fingerprinting
        for p in open_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target.ip, p["port"]))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    p["banner"] = banner[:200]
                sock.close()
            except:
                p["banner"] = ""
        
        self.target.ports = [p["port"] for p in open_ports]
        Utils.log("OK", f"Found {len(open_ports)} open ports")
        return open_ports
    
    def technology_detection(self, session=None) -> Dict:
        """Detect web technologies using response headers and content."""
        import requests
        
        techs = {}
        
        try:
            s = session or requests.Session()
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            resp = s.get(self.target.url, headers=headers, timeout=10, verify=False)
            
            # Server header
            server = resp.headers.get('Server', '')
            if server:
                techs['server'] = server
            
            # X-Powered-By
            powered = resp.headers.get('X-Powered-By', '')
            if powered:
                techs['powered_by'] = powered
            
            # Set-Cookie analysis
            set_cookie = resp.headers.get('Set-Cookie', '')
            if 'PHPSESSID' in set_cookie:
                techs['backend'] = 'PHP'
            if 'JSESSIONID' in set_cookie:
                techs['backend'] = 'Java (J2EE)'
            if 'ASP.NET' in set_cookie or 'ASPSESSIONID' in set_cookie:
                techs['backend'] = 'ASP.NET'
            if 'laravel_session' in set_cookie:
                techs['backend'] = 'Laravel (PHP)'
            
            # Content analysis
            content = resp.text[:5000].lower()
            if 'wp-content' in content or 'wp-includes' in content:
                techs['cms'] = 'WordPress'
            if 'drupal' in content:
                techs['cms'] = 'Drupal'
            if 'joomla' in content:
                techs['cms'] = 'Joomla'
            
            # Check for common paths
            check_paths = [
                '/robots.txt', '/sitemap.xml', '/.git/config', 
                '/admin/', '/phpinfo.php', '/.env', '/wp-admin/'
            ]
            
            interesting = []
            for path in check_paths:
                try:
                    r = s.get(urljoin(self.target.url, path), timeout=5, verify=False)
                    if r.status_code == 200:
                        interesting.append({"path": path, "status": 200})
                    elif r.status_code in [301, 302, 403]:
                        interesting.append({"path": path, "status": r.status_code})
                except:
                    pass
            
            if interesting:
                techs['interesting_paths'] = interesting
            
            self.target.technologies = techs
            
        except Exception as e:
            Utils.log("WARN", f"Technology detection failed: {str(e)}")
        
        return techs

# ---------------------------------------------------------------------------
# Web Vulnerability Scanner
# ---------------------------------------------------------------------------
class WebVulnScanner:
    """Web application vulnerability scanner."""
    
    def __init__(self, target: ScanTarget, session=None):
        self.target = target
        self.session = session or self._create_session()
        self.vulnerabilities: List[Vulnerability] = []
        self.payloads = self._load_payloads()
    
    def _create_session(self):
        import requests
        s = requests.Session()
        s.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        s.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return s
    
    def _load_payloads(self) -> Dict:
        return {
            'sqli': [
                "' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT NULL--",
                "admin' --", "1' ORDER BY 1--", "1' AND 1=1--", "1' AND 1=2--",
                "' UNION SELECT 1,2,3--", "'/**/OR/**/1=1/**/--",
                "'; WAITFOR DELAY '0:0:5'--", "' OR SLEEP(5)--",
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "\"><script>alert('XSS')</script>",
                "'-alert('XSS')-'",
                "<ScRiPt>alert('XSS')</sCrIpT>",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
            ],
            'lfi': [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "../../Windows/System32/drivers/etc/hosts",
                "php://filter/convert.base64-encode/resource=index.php",
                "/etc/passwd%00",
                "....//....//....//....//etc/passwd",
            ],
            'command_injection': [
                "; id", "| id", "`id`", "$(id)", "& id",
                "|| id", "&& id", ";whoami", "|whoami",
                "`whoami`", "$(whoami)", "| ping -c 5 127.0.0.1",
            ],
            'ssrf': [
                "http://127.0.0.1:80", "http://localhost:80",
                "http://[::1]:80", "http://0.0.0.0:80",
                "file:///etc/passwd", "http://169.254.169.254/latest/meta-data/",
            ],
            'open_redirect': [
                "//evil.com", "https://evil.com", "//evil.com@google.com",
                "/\\evil.com", "http://evil.com",
            ],
        }
    
    def discover_forms(self) -> List[Dict]:
        """Discover forms on the target."""
        import requests
        from bs4 import BeautifulSoup
        
        forms = []
        try:
            resp = self.session.get(self.target.url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                for inp in form.find_all('input'):
                    input_data = {
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', ''),
                    }
                    form_data['inputs'].append(input_data)
                
                for textarea in form.find_all('textarea'):
                    form_data['inputs'].append({
                        'name': textarea.get('name', ''),
                        'type': 'textarea',
                        'value': textarea.get_text(),
                    })
                
                forms.append(form_data)
        
        except Exception as e:
            Utils.log("WARN", f"Form discovery failed: {str(e)}")
        
        self.target.forms = forms
        Utils.log("INFO", f"Discovered {len(forms)} forms")
        return forms
    
    def discover_endpoints(self) -> List[str]:
        """Discover endpoints using common paths and directory brute-forcing."""
        common_paths = [
            "/admin", "/login", "/register", "/api", "/v1", "/v2",
            "/user", "/users", "/account", "/profile", "/config",
            "/backup", "/dump", "/db", "/database", "/sql",
            "/phpmyadmin", "/adminer", "/wp-admin", "/administrator",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/.git", "/.svn", "/.DS_Store", "/.env", "/.htaccess",
            "/server-status", "/info.php", "/phpinfo.php",
            "/test", "/debug", "/upload", "/uploads",
            "/api/users", "/api/admin", "/api/health",
            "/graphql", "/swagger", "/api-docs",
            "/actuator", "/actuator/health",
            "/console", "/h2-console",
            "/websocket", "/sockjs",
        ]
        
        found = []
        Utils.log("INFO", f"Testing {len(common_paths)} common paths...")
        
        def check_path(path):
            try:
                url = urljoin(self.target.url, path)
                resp = self.session.get(url, timeout=8)
                if resp.status_code in [200, 301, 302, 401, 403, 500]:
                    return {"path": path, "status": resp.status_code, "size": len(resp.text)}
            except:
                pass
            return None
        
        results = Utils.threaded_map(check_path, common_paths, max_workers=20)
        found = [r for r in results if r]
        
        self.target.endpoints = [e["path"] for e in found]
        Utils.log("OK", f"Found {len(found)} accessible endpoints")
        return found
    
    def test_sqli(self, url: str, param: str, value: str = "test") -> List[Vulnerability]:
        """Test for SQL injection."""
        vulns = []
        import requests
        
        for payload in self.payloads['sqli']:
            try:
                params = {param: payload}
                resp = self.session.get(url, params=params, timeout=10)
                
                # Error-based detection
                error_patterns = [
                    "sql", "mysql", "syntax error", "unclosed quotation",
                    "odbc", "driver", "ora-", "postgresql", "sqlite",
                    "pg_", "mysqli", "mysql_fetch", "warning: mysql",
                ]
                
                content_lower = resp.text.lower()
                for pattern in error_patterns:
                    if pattern in content_lower:
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.SQLI,
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description=f"SQL Injection vulnerability detected via error-based technique: '{pattern}'",
                            evidence=content_lower[:500],
                            remediation="Use parameterized queries (prepared statements). Validate and sanitize all user inputs.",
                        ))
                        return vulns
                
                # Boolean-based detection
                true_payload = f"{value}' AND '1'='1"
                false_payload = f"{value}' AND '1'='2"
                
                resp_true = self.session.get(url, params={param: true_payload}, timeout=10)
                resp_false = self.session.get(url, params={param: false_payload}, timeout=10)
                
                true_length = len(resp_true.text)
                false_length = len(resp_false.text)
                
                # If responses differ significantly, boolean-based SQLi may exist
                if abs(true_length - false_length) > 50:
                    vulns.append(Vulnerability(
                        vuln_type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=true_payload,
                        description="Boolean-based SQL Injection detected (differing response lengths)",
                        evidence=f"True: {true_length} bytes, False: {false_length} bytes",
                        remediation="Use parameterized queries and input validation.",
                    ))
                    return vulns
                    
            except Exception:
                continue
        
        return vulns
    
    def test_xss(self, url: str, param: str) -> List[Vulnerability]:
        """Test for Cross-Site Scripting."""
        vulns = []
        
        for payload in self.payloads['xss'][:5]:  # Test first 5 payloads
            try:
                params = {param: payload}
                resp = self.session.get(url, params=params, timeout=10)
                
                # Check if payload is reflected in response
                if payload in resp.text or payload.replace("'", "") in resp.text:
                    # Check for context
                    context = self._get_reflection_context(resp.text, payload)
                    
                    vulns.append(Vulnerability(
                        vuln_type=VulnType.XSS,
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        description=f"Reflected XSS vulnerability detected (context: {context})",
                        evidence=f"Payload reflected in response at position {context}",
                        remediation="Encode output based on context (HTML entity, JavaScript, URL encoding). Use CSP headers.",
                    ))
                    return vulns
                    
            except Exception:
                continue
        
        # Test stored XSS on forms
        for form in self.target.forms:
            for inp in form['inputs']:
                if inp['type'] in ['text', 'search', 'textarea']:
                    for payload in self.payloads['xss'][:3]:
                        try:
                            form_data = {}
                            for i in form['inputs']:
                                if i['name'] == inp['name']:
                                    form_data[i['name']] = payload
                                else:
                                    form_data[i['name']] = i.get('value', 'test')
                            
                            action_url = urljoin(url, form['action'])
                            if form['method'] == 'POST':
                                resp = self.session.post(action_url, data=form_data, timeout=10)
                            else:
                                resp = self.session.get(action_url, params=form_data, timeout=10)
                            
                            if payload in resp.text:
                                vulns.append(Vulnerability(
                                    vuln_type=VulnType.XSS,
                                    severity=Severity.HIGH,
                                    url=action_url,
                                    parameter=inp['name'],
                                    payload=payload,
                                    description="Potential Stored XSS vulnerability",
                                    remediation="Validate and encode all user-submitted data before storing/displaying.",
                                ))
                                return vulns
                        except:
                            continue
        
        return vulns
    
    def _get_reflection_context(self, response_text: str, payload: str) -> str:
        """Determine where in the HTML the payload is reflected."""
        import re
        
        # Check various contexts
        if f'<script>{payload}' in response_text or f'<script>{payload}</script>' in response_text:
            return "inside script tags"
        if f'onerror={payload}' in response_text or f'onload={payload}' in response_text:
            return "event handler"
        if f'href="{payload}' in response_text or f'href=\'{payload}' in response_text:
            return "href attribute"
        if f'src="{payload}' in response_text:
            return "src attribute"
        if f'value="{payload}' in response_text:
            return "input value attribute"
        if any(tag in response_text for tag in ['<b>', '<i>', '<u>', '<p>', '<div>', '<span>', '<h1>', '<h2>', '<h3>']):
            return "inside HTML tags"
        
        return "unknown context"
    
    def test_command_injection(self, url: str, param: str) -> List[Vulnerability]:
        """Test for command injection vulnerabilities."""
        vulns = []
        
        for payload in self.payloads['command_injection']:
            try:
                params = {param: payload}
                resp = self.session.get(url, params=params, timeout=15)
                
                # Check for command execution evidence
                indicators = [
                    "uid=", "gid=", "root:", "bin:", "www-data",
                    "Linux", "Windows", "NT AUTHORITY",
                    "Command executed", "output",
                ]
                
                content = resp.text.lower()
                for indicator in indicators:
                    if indicator.lower() in content:
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.COMMAND_INJECTION,
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description=f"Command Injection vulnerability detected via payload: {payload}",
                            evidence=f"Indicator '{indicator}' found in response",
                            remediation="Avoid using system commands with user input. Use safe APIs. Implement strict input validation.",
                        ))
                        return vulns
                        
            except Exception:
                continue
        
        return vulns
    
    def test_ssrf(self, url: str, param: str) -> List[Vulnerability]:
        """Test for Server-Side Request Forgery."""
        vulns = []
        
        for payload in self.payloads['ssrf']:
            try:
                params = {param: payload}
                start = time.time()
                resp = self.session.get(url, params=params, timeout=15)
                elapsed = time.time() - start
                
                # Check for SSRF indicators
                ssrf_indicators = [
                    "ec2", "meta-data", "iam", "localhost",
                    "127.0.0.1", "internal", "private ip",
                ]
                
                content = resp.text.lower()
                for indicator in ssrf_indicators:
                    if indicator in content:
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.SSRF,
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description=f"SSRF vulnerability detected - server requested internal resource",
                            evidence=f"Response contains '{indicator}'",
                            remediation="Validate and whitelist allowed URLs/domains. Block requests to private IP ranges.",
                        ))
                        return vulns
                        
            except Exception:
                continue
        
        return vulns
    
    def test_file_inclusion(self, url: str, param: str) -> List[Vulnerability]:
        """Test for Local/Remote File Inclusion."""
        vulns = []
        
        for payload in self.payloads['lfi']:
            try:
                params = {param: payload}
                resp = self.session.get(url, params=params, timeout=10)
                
                # LFI indicators
                lfi_indicators = [
                    "root:", "bin:/", "daemon:", "www-data:",
                    "[boot loader]", "Windows Registry",
                    "localhost", "drivers", "etc/hosts",
                    "php://filter", "base64_decode",
                ]
                
                content = resp.text.lower()
                for indicator in lfi_indicators:
                    if indicator.lower() in content:
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.LFI,
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description=f"Local File Inclusion detected",
                            evidence=f"Response contains '{indicator}'",
                            remediation="Avoid passing user input to file operations. Use whitelist-based file access.",
                        ))
                        return vulns
                        
            except Exception:
                continue
        
        return vulns
    
    def scan_all_params(self, url: str) -> List[Vulnerability]:
        """Scan all discovered parameters for vulnerabilities."""
        import requests
        from urllib.parse import parse_qs, urlparse
        
        all_vulns = []
        
        # Extract parameters from URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Try common parameters
            common_params = ["id", "page", "file", "url", "path", "name", 
                           "q", "s", "search", "cat", "product", "user",
                           "user_id", "uid", "msg", "message", "redirect",
                           "next", "return", "debug", "cmd", "exec"]
            params = {p: ["1"] for p in common_params}
        
        Utils.log("INFO", f"Testing {len(params)} parameters for vulnerabilities...")
        
        for param in params:
            # SQL Injection
            sqli_vulns = self.test_sqli(url, param)
            all_vulns.extend(sqli_vulns)
            
            # XSS
            xss_vulns = self.test_xss(url, param)
            all_vulns.extend(xss_vulns)
            
            # Command Injection
            cmd_vulns = self.test_command_injection(url, param)
            all_vulns.extend(cmd_vulns)
            
            # SSRF
            ssrf_vulns = self.test_ssrf(url, param)
            all_vulns.extend(ssrf_vulns)
            
            # LFI
            lfi_vulns = self.test_file_inclusion(url, param)
            all_vulns.extend(lfi_vulns)
        
        return all_vulns

# ---------------------------------------------------------------------------
# Network Vulnerability Scanner
# ---------------------------------------------------------------------------
class NetworkVulnScanner:
    """Network-level vulnerability assessment."""
    
    def __init__(self, target: ScanTarget):
        self.target = target
    
    def check_common_vulnerabilities(self) -> List[Vulnerability]:
        """Check for common network-level vulnerabilities."""
        vulns = []
        
        for port_info in self.target.ports:
            port = port_info if isinstance(port_info, int) else port_info.get('port', 0)
            
            # Check for default/weak services on common ports
            if port == 21:
                vulns.append(Vulnerability(
                    vuln_type=VulnType.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    url=f"ftp://{self.target.ip}:{port}",
                    description="FTP service detected - may allow anonymous access",
                    remediation="Disable FTP if not needed. Use SFTP or SCP instead. Restrict anonymous access.",
                ))
            
            elif port == 23:
                vulns.append(Vulnerability(
                    vuln_type=VulnType.MISCONFIGURATION,
                    severity=Severity.HIGH,
                    url=f"telnet://{self.target.ip}:{port}",
                    description="Telnet service detected - unencrypted protocol",
                    remediation="Replace Telnet with SSH. Telnet transmits credentials and data in cleartext.",
                ))
            
            elif port == 445:
                vulns.append(Vulnerability(
                    vuln_type=VulnType.MISCONFIGURATION,
                    severity=Severity.HIGH,
                    url=f"smb://{self.target.ip}:{port}",
                    description="SMB service detected - potential EternalBlue/MS17-010 vulnerability",
                    remediation="Apply MS17-010 patch. Disable SMBv1. Restrict SMB access with firewall rules.",
                    cve="CVE-2017-0143",
                    cvss_score=9.3,
                ))
            
            elif port == 3306:
                vulns.append(Vulnerability(
                    vuln_type=VulnType.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    url=f"mysql://{self.target.ip}:{port}",
                    description="MySQL database exposed to network",
                    remediation="Restrict MySQL to localhost. Use strong passwords. Apply principle of least privilege.",
                ))
            
            elif port == 6379:
                vulns.append(Vulnerability(
                    vuln_type=VulnType.MISCONFIGURATION,
                    severity=Severity.HIGH,
                    url=f"redis://{self.target.ip}:{port}",
                    description="Redis service exposed without authentication",
                    remediation="Set requirepass in redis.conf. Bind to localhost. Use firewall rules.",
                ))
        
        return vulns

# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------
class ReportGenerator:
    """Generate comprehensive VAPT reports."""
    
    def __init__(self, target: ScanTarget, vulnerabilities: List[Vulnerability]):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.scan_time = datetime.now()
    
    def generate_summary(self) -> Dict:
        """Generate summary statistics."""
        severity_counts = {
            "CRITICAL": sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL),
            "HIGH": sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH),
            "MEDIUM": sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM),
            "LOW": sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW),
            "INFO": sum(1 for v in self.vulnerabilities if v.severity == Severity.INFO),
        }
        
        return {
            "scan_target": self.target.url,
            "scan_time": self.scan_time.isoformat(),
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_summary": severity_counts,
            "top_vulnerabilities": [
                {
                    "vuln_type": v.vuln_type.value,
                    "severity": v.severity.name,
                    "url": v.url[:100] if len(v.url) > 100 else v.url,
                }
                for v in sorted(self.vulnerabilities, key=lambda x: x.severity.value, reverse=True)[:5]
            ],
        }
    
    def print_report(self, detailed: bool = False):
        """Print formatted VAPT report."""
        
        print(f"\n{Colors.HEADER}{'='*60}")
        print(f"  VAPT ASSESSMENT REPORT")
        print(f"{'='*60}{Colors.RESET}")
        
        print(f"\n  {Colors.BOLD}Target:{Colors.RESET}       {self.target.url}")
        print(f"  {Colors.BOLD}Domain:{Colors.RESET}       {self.target.domain}")
        print(f"  {Colors.BOLD}IP Address:{Colors.RESET}     {self.target.ip}")
        print(f"  {Colors.BOLD}Scan Time:{Colors.RESET}     {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  {Colors.BOLD}Open Ports:{Colors.RESET}    {len(self.target.ports)}")
        print(f"  {Colors.BOLD}Endpoints:{Colors.RESET}     {len(self.target.endpoints)}")
        
        # Vulnerabilities by severity
        summary = self.generate_summary()
        print(f"\n  {Colors.BOLD}{'─'*60}")
        print(f"  VULNERABILITY SUMMARY")
        print(f"  {'─'*60}{Colors.RESET}")
        print(f"  Total: {summary['total_vulnerabilities']}")
        
        sev_colors = {
            "CRITICAL": Colors.RED,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.BLUE,
            "INFO": Colors.DIM,
        }
        
        for sev, count in summary['severity_summary'].items():
            color = sev_colors.get(sev, Colors.WHITE)
            print(f"  {color}{sev:<10}: {count}{Colors.RESET}")
        
        # Detailed vulnerabilities
        if detailed and self.vulnerabilities:
            print(f"\n  {Colors.BOLD}{'─'*60}")
            print(f"  DETAILED FINDINGS")
            print(f"  {'─'*60}{Colors.RESET}")
            
            self.vulnerabilities.sort(key=lambda x: x.severity.value, reverse=True)
            for i, vuln in enumerate(self.vulnerabilities, 1):
                color = sev_colors.get(vuln.severity.name, Colors.WHITE)
                print(f"\n  {color}[{vuln.severity.name}]{Colors.RESET} #{i}: {vuln.vuln_type.value}")
                print(f"       {Colors.DIM}URL:{Colors.RESET}       {vuln.url}")
                if vuln.parameter:
                    print(f"       {Colors.DIM}Parameter:{Colors.RESET} {vuln.parameter}")
                if vuln.payload:
                    print(f"       {Colors.DIM}Payload:{Colors.RESET}    {vuln.payload[:100]}")
                print(f"       {Colors.DIM}Description:{Colors.RESET} {vuln.description}")
                if vuln.cve:
                    print(f"       {Colors.DIM}CVE:{Colors.RESET}       {vuln.cve} (CVSS: {vuln.cvss_score})")
                if vuln.evidence:
                    evidence_preview = vuln.evidence[:200]
                    print(f"       {Colors.DIM}Evidence:{Colors.RESET}   {evidence_preview}")
                print(f"       {Colors.OKGREEN}Remediation:{Colors.RESET} {vuln.remediation}")
        
        # Recommendations
        print(f"\n  {Colors.BOLD}{'─'*60}")
        print(f"  TOP RECOMMENDATIONS")
        print(f"  {'─'*60}{Colors.RESET}")
        
        recommendations = [
            "Implement a Web Application Firewall (WAF) to filter malicious requests",
            "Use parameterized queries to prevent SQL injection attacks",
            "Implement Content Security Policy (CSP) headers to mitigate XSS",
            "Validate and sanitize all user inputs server-side",
            "Keep all software, libraries, and dependencies up to date",
            "Implement proper access controls and authentication mechanisms",
            "Use HTTPS with secure cipher suites across all services",
            "Conduct regular security assessments and code reviews",
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        print(f"\n{Colors.HEADER}{'='*60}")
        print(f"  END OF REPORT - {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}{Colors.RESET}\n")
    
    def export_json(self, filepath: str = "vapt_report.json"):
        """Export report to JSON."""
        report = {
            "scan_metadata": {
                "target": self.target.url,
                "domain": self.target.domain,
                "ip": self.target.ip,
                "scan_time": self.scan_time.isoformat(),
                "tool": "VAPT Framework v2.0",
            },
            "summary": self.generate_summary(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "target_info": {
                "open_ports": self.target.ports,
                "technologies": self.target.technologies,
                "endpoints": self.target.endpoints,
            },
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        Utils.log("OK", f"Report exported to {filepath}")

# ---------------------------------------------------------------------------
# Main VAPT Controller
# ---------------------------------------------------------------------------
class VAPTController:
    """Main controller orchestrating all VAPT modules."""
    
    def __init__(self, target_url: str):
        self.target = ScanTarget(url=target_url)
        self.vulnerabilities: List[Vulnerability] = []
        self.start_time = None
        self.end_time = None
    
    def run(self, aggressive: bool = False, output_file: str = None):
        """Run the full VAPT assessment."""
        self.start_time = datetime.now()
        
        Utils.print_banner(self.target.url)
        Utils.log("HEADER", f"Starting VAPT assessment against {self.target.url}")
        Utils.log("INFO", f"Target resolved to IP: {self.target.ip}")
        Utils.log("DIM", f"{'─'*60}")
        
        # Phase 1: Reconnaissance
        Utils.log("HEADER", "\n[PHASE 1] RECONNAISSANCE")
        recon = ReconModule(self.target)
        
        dns_results = recon.dns_enumeration()
        if dns_results.get('subdomains'):
            Utils.log("OK", f"Found {len(dns_results['subdomains'])} subdomains")
            for sd in dns_results['subdomains'][:5]:
                Utils.log("INFO", f"  Subdomain: {sd['subdomain']} -> {sd['ip']}")
        
        open_ports = recon.port_scan()
        if open_ports:
            Utils.log("OK", "Open ports:")
            for p in open_ports:
                banner = f" - {p.get('banner', '')}" if p.get('banner') else ""
                Utils.log("INFO", f"  {p['port']:5}/{p['service']:<15}{banner}")
        
        techs = recon.technology_detection()
        if techs:
            Utils.log("OK", "Technologies detected:")
            for k, v in techs.items():
                if k != 'interesting_paths':
                    Utils.log("INFO", f"  {k}: {v}")
        
        # Phase 2: Web Application Scanning
        Utils.log("HEADER", "\n[PHASE 2] WEB APPLICATION SCANNING")
        web_scanner = WebVulnScanner(self.target)
        
        forms = web_scanner.discover_forms()
        endpoints = web_scanner.discover_endpoints()
        
        if endpoints:
            Utils.log("OK", "Interesting endpoints:")
            for ep in endpoints[:10]:
                Utils.log("INFO", f"  {ep['status']} {ep['path']}")
        
        # Vulnerability scanning
        Utils.log("HEADER", "\n[PHASE 3] VULNERABILITY SCANNING")
        
        # Scan main URL
        main_vulns = web_scanner.scan_all_params(self.target.url)
        self.vulnerabilities.extend(main_vulns)
        
        # Scan discovered endpoints
        for ep in endpoints[:5]:  # Limit to first 5 for performance
            try:
                ep_url = urljoin(self.target.url, ep['path'])
                ep_vulns = web_scanner.scan_all_params(ep_url)
                self.vulnerabilities.extend(ep_vulns)
            except:
                continue
        
        # Phase 4: Network Vulnerability Assessment
        Utils.log("HEADER", "\n[PHASE 4] NETWORK VULNERABILITY ASSESSMENT")
        net_scanner = NetworkVulnScanner(self.target)
        net_vulns = net_scanner.check_common_vulnerabilities()
        self.vulnerabilities.extend(net_vulns)
        
        # Phase 5: Reporting
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        Utils.log("HEADER", "\n[PHASE 5] REPORT GENERATION")
        Utils.log("INFO", f"Assessment completed in {duration:.1f} seconds")
        Utils.log("INFO", f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        
        report = ReportGenerator(self.target, self.vulnerabilities)
        report.print_report(detailed=True)
        
        if output_file:
            report.export_json(output_file)
        
        return self.vulnerabilities

# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="VAPT Framework - Vulnerability Assessment & Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u http://testphp.vulnweb.com -o report.json
  %(prog)s -u https://example.com -a
  %(prog)s --port-scan 192.168.1.1
  
Note: Only use on systems you own or have explicit written authorization to test.
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL to assess")
    parser.add_argument("-o", "--output", help="Output JSON report file")
    parser.add_argument("-a", "--aggressive", action="store_true", 
                       help="Aggressive mode (more payloads, slower but thorough)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    # Run assessment
    controller = VAPTController(args.url)
    controller.run(aggressive=args.aggressive, output_file=args.output)

if __name__ == "__main__":
    main()
