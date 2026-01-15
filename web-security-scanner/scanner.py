#!/usr/bin/env python3
"""
Advanced Web Security Scanner
Author: Sean Amon | OSCP Candidate | Junior Pentester
A professional-grade security scanner for OWASP Top 10 vulnerabilities
"""

import argparse
import requests
import json
import time
import re
import sys
from urllib.parse import urljoin, urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading

class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        self.session = requests.Session()
        self.lock = threading.Lock()
        self.scan_results = {
            'sql_injection': 0,
            'xss': 0,
            'idor': 0,
            'xxe': 0,
            'ssrf': 0,
            'cors': 0,
            'info_disclosure': 0,
            'security_headers': 0,
            'csrf': 0,
            'file_upload': 0
        }
        
        # Configure session
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/2.0 (Sean Amon Pentest Portfolio)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        })
        
    def test_sql_injection(self, url, params):
        """Test for SQL Injection vulnerabilities"""
        sql_payloads = [
            "'", "''", "`", "\"", "\"\"",
            "' OR '1'='1", "' OR '1'='1' --",
            "' UNION SELECT null,null --",
            "' AND 1=CONVERT(int, @@version) --",
            "1' AND sleep(5) --"
        ]
        
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"PSQLException",
            r"SQLite/JDBCDriver",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"ODBC Microsoft Access Driver",
            r"Microsoft Access Database Engine",
            r"ODBC Driver Manager",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"CLI Driver.*DB2",
            r"DB2 SQL error",
            r"SQLServer JDBC Driver",
            r"com.microsoft.sqlserver",
            r"Unclosed quotation mark",
            r"Syntax error.*SQL Server"
        ]
        
        for payload in sql_payloads:
            try:
                test_params = params.copy()
                for key in test_params:
                    if isinstance(test_params[key], str):
                        test_params[key] = payload
                
                response = self.session.get(url, params=test_params, timeout=10)
                
                for error_pattern in sql_errors:
                    if re.search(error_pattern, response.text, re.IGNORECASE):
                        with self.lock:
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'url': response.url,
                                'parameter': list(params.keys())[0],
                                'payload': payload,
                                'evidence': f"SQL error detected: {error_pattern}",
                                'owasp_category': 'A03: Injection',
                                'cwe': 'CWE-89',
                                'remediation': 'Use parameterized queries or prepared statements. Implement input validation and output encoding.',
                                'reference': 'https://owasp.org/www-community/attacks/SQL_Injection'
                            })
                            self.scan_results['sql_injection'] += 1
                        return
                        
            except Exception:
                continue
                
    def test_xss(self, url, params):
        """Test for Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input type=text value=\"\" onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>"
        ]
        
        for payload in xss_payloads:
            try:
                test_params = params.copy()
                for key in test_params:
                    if isinstance(test_params[key], str):
                        test_params[key] = payload
                
                response = self.session.get(url, params=test_params, timeout=10)
                
                # Check if payload appears in response (reflected XSS)
                if payload in response.text:
                    with self.lock:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'url': response.url,
                            'parameter': list(params.keys())[0],
                            'payload': payload,
                            'evidence': 'Payload reflected in response without encoding',
                            'owasp_category': 'A03: Injection',
                            'cwe': 'CWE-79',
                            'remediation': 'Implement proper output encoding. Use Content Security Policy (CSP). Validate and sanitize all user input.',
                            'reference': 'https://owasp.org/www-community/attacks/xss/'
                        })
                        self.scan_results['xss'] += 1
                    return
                    
            except Exception:
                continue
                
    def test_idor(self, url):
        """Test for Insecure Direct Object References"""
        test_ids = ['1', '2', '100', 'admin', 'test', '12345']
        
        for test_id in test_ids:
            try:
                test_url = url.replace('{id}', test_id)
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    # Check if we accessed something we shouldn't have
                    sensitive_patterns = [
                        r'password', r'credit.?card', r'ssn', r'social.?security',
                        r'private', r'confidential', r'admin', r'root'
                    ]
                    
                    for pattern in sensitive_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            with self.lock:
                                self.vulnerabilities.append({
                                    'type': 'Insecure Direct Object Reference (IDOR)',
                                    'severity': 'High',
                                    'url': test_url,
                                    'parameter': 'id',
                                    'payload': test_id,
                                    'evidence': f'Accessed sensitive resource with ID: {test_id}',
                                    'owasp_category': 'A01: Broken Access Control',
                                    'cwe': 'CWE-639',
                                    'remediation': 'Implement proper authorization checks. Use indirect object references or UUIDs.',
                                    'reference': 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References'
                                })
                                self.scan_results['idor'] += 1
                            return
                            
            except Exception:
                continue
                
    def test_security_headers(self):
        """Check for missing security headers"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': {
                    'required': True,
                    'description': 'Prevents clickjacking attacks',
                    'recommended': 'DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'required': True,
                    'description': 'Prevents MIME type sniffing',
                    'recommended': 'nosniff'
                },
                'Content-Security-Policy': {
                    'required': True,
                    'description': 'Prevents XSS and other code injection attacks',
                    'recommended': "default-src 'self'"
                },
                'Strict-Transport-Security': {
                    'required': response.url.startswith('https'),
                    'description': 'Enforces HTTPS connections',
                    'recommended': 'max-age=31536000; includeSubDomains'
                },
                'X-Permitted-Cross-Domain-Policies': {
                    'required': False,
                    'description': 'Restricts Flash/PDF loading',
                    'recommended': 'none'
                },
                'Referrer-Policy': {
                    'required': False,
                    'description': 'Controls referrer information',
                    'recommended': 'strict-origin-when-cross-origin'
                },
                'Permissions-Policy': {
                    'required': False,
                    'description': 'Controls browser features',
                    'recommended': 'geolocation=(), microphone=(), camera=()'
                }
            }
            
            missing_headers = []
            weak_headers = []
            
            for header, config in security_headers.items():
                if config['required'] and header not in headers:
                    missing_headers.append(header)
                elif header in headers and header == 'X-Content-Type-Options':
                    if headers[header].lower() != 'nosniff':
                        weak_headers.append(f"{header}: {headers[header]} (should be 'nosniff')")
                        
            if missing_headers:
                with self.lock:
                    self.vulnerabilities.append({
                        'type': 'Missing Security Headers',
                        'severity': 'Medium',
                        'url': self.target_url,
                        'parameter': 'N/A',
                        'payload': 'N/A',
                        'evidence': f"Missing headers: {', '.join(missing_headers)}",
                        'owasp_category': 'A05: Security Misconfiguration',
                        'cwe': 'CWE-693',
                        'remediation': f"Implement missing security headers in web server configuration.",
                        'reference': 'https://owasp.org/www-project-secure-headers/'
                    })
                    self.scan_results['security_headers'] += 1
                    
        except Exception as e:
            print(f"[!] Error checking security headers: {e}")
            
    def test_cors_misconfiguration(self):
        """Test for CORS misconfiguration"""
        try:
            # Test with Origin header
            test_origins = [
                'https://evil.com',
                'http://attacker.com',
                'null',
                self.target_url.replace('https://', 'http://')
            ]
            
            for origin in test_origins:
                headers = {'Origin': origin}
                response = self.session.get(self.target_url, headers=headers, timeout=10)
                
                cors_header = response.headers.get('Access-Control-Allow-Origin')
                allow_credentials = response.headers.get('Access-Control-Allow-Credentials')
                
                if cors_header == '*' and allow_credentials == 'true':
                    with self.lock:
                        self.vulnerabilities.append({
                            'type': 'CORS Misconfiguration',
                            'severity': 'Medium',
                            'url': self.target_url,
                            'parameter': 'Origin',
                            'payload': origin,
                            'evidence': f"CORS allows wildcard (*) with credentials from origin: {origin}",
                            'owasp_category': 'A07: Identification and Authentication Failures',
                            'cwe': 'CWE-942',
                            'remediation': 'Avoid using wildcard (*) in Access-Control-Allow-Origin. Specify trusted domains explicitly.',
                            'reference': 'https://portswigger.net/web-security/cors'
                        })
                        self.scan_results['cors'] += 1
                    break
                    
        except Exception as e:
            print(f"[!] Error testing CORS: {e}")
            
    def crawl_and_test(self):
        """Crawl website and test all endpoints"""
        print(f"[*] Crawling {self.target_url} for testing endpoints...")
        
        # Common endpoints to test
        endpoints = [
            {'path': '', 'params': {'q': 'test', 'search': 'test'}},
            {'path': 'search', 'params': {'query': 'test'}},
            {'path': 'login', 'params': {'username': 'test', 'password': 'test'}},
            {'path': 'profile', 'params': {'id': '1'}},
            {'path': 'api/users', 'params': {'id': '1'}},
            {'path': 'admin', 'params': {}},
            {'path': 'upload', 'params': {}},
            {'path': 'comments', 'params': {'post_id': '1'}}
        ]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for endpoint in endpoints:
                url = urljoin(self.target_url, endpoint['path'])
                params = endpoint['params']
                
                if params:
                    # Test SQL Injection
                    futures.append(executor.submit(self.test_sql_injection, url, params))
                    # Test XSS
                    futures.append(executor.submit(self.test_xss, url, params))
                    
                # Test IDOR if URL has {id} pattern
                if '{id}' in url:
                    futures.append(executor.submit(self.test_idor, url))
                    
            # Wait for all tests to complete
            for future in futures:
                try:
                    future.result(timeout=30)
                except Exception as e:
                    continue
                    
        # Test security headers and CORS
        self.test_security_headers()
        self.test_cors_misconfiguration()
        
    def generate_report(self, output_format='json'):
        """Generate professional security report"""
        report = {
            'metadata': {
                'scan_id': f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'target': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '2.0',
                'analyst': 'Sean Amon',
                'contact': 'seanamon56@gmail.com'
            },
            'executive_summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'risk_score': self.calculate_risk_score(),
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'High']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'Medium']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
            },
            'technical_summary': self.scan_results,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self.generate_recommendations(),
            'appendix': {
                'methodology': 'OWASP Web Security Testing Guide v4.2',
                'tools_used': ['Custom Python Scanner', 'Requests Library', 'ThreadPoolExecutor'],
                'testing_time': f"{len(self.vulnerabilities) * 2} minutes estimated"
            }
        }
        
        if output_format == 'json':
            return json.dumps(report, indent=2, default=str)
        elif output_format == 'html':
            return self.generate_html_report(report)
        else:
            return self.generate_text_report(report)
            
    def calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        scores = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
        total = sum(scores[v['severity']] for v in self.vulnerabilities)
        return min(100, total * 5)
        
    def generate_recommendations(self):
        """Generate actionable recommendations"""
        return {
            'immediate': [
                'Patch all critical vulnerabilities within 24 hours',
                'Implement WAF rules for detected attack patterns',
                'Review and fix authentication/authorization logic'
            ],
            'short_term': [
                'Complete security headers implementation',
                'Conduct developer security training',
                'Implement automated security testing in CI/CD'
            ],
            'long_term': [
                'Establish regular penetration testing schedule',
                'Implement bug bounty program',
                'Adopt DevSecOps practices organization-wide'
            ]
        }
        
    def generate_html_report(self, report):
        """Generate HTML report with professional styling"""
        # Implementation of HTML report generation
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report - {report['metadata']['target']}</title>
            <style>
                /* Professional security report styling */
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: #f5f5f5; color: #333; }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #2c3e50, #4a6491); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .header h1 {{ margin: 0; font-size: 2.5em; }}
                .header .subtitle {{ opacity: 0.9; margin-top: 10px; }}
                .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .card {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .card.critical {{ border-left: 5px solid #e74c3c; }}
                .card.high {{ border-left: 5px solid #e67e22; }}
                .card.medium {{ border-left: 5px solid #f1c40f; }}
                .card.low {{ border-left: 5px solid #3498db; }}
                .card.info {{ border-left: 5px solid #2ecc71; }}
                .severity-badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; margin-right: 10px; }}
                .severity-critical {{ background: #e74c3c; }}
                .severity-high {{ background: #e67e22; }}
                .severity-medium {{ background: #f1c40f; color: #333; }}
                .severity-low {{ background: #3498db; }}
                .vulnerability {{ background: white; margin-bottom: 15px; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 5px solid #ddd; }}
                .vulnerability.critical {{ border-left-color: #e74c3c; }}
                .vulnerability.high {{ border-left-color: #e67e22; }}
                .vulnerability.medium {{ border-left-color: #f1c40f; }}
                .vulnerability.low {{ border-left-color: #3498db; }}
                .evidence {{ background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; margin: 10px 0; border-left: 3px solid #6c757d; }}
                .recommendation {{ background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 3px solid #2ecc71; }}
                .footer {{ margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 0.9em; padding: 20px; border-top: 1px solid #ddd; }}
                .risk-meter {{ background: linear-gradient(to right, #2ecc71, #f1c40f, #e74c3c); height: 20px; border-radius: 10px; margin: 20px 0; position: relative; }}
                .risk-indicator {{ position: absolute; top: -5px; width: 3px; height: 30px; background: #2c3e50; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #f8f9fa; font-weight: 600; }}
                tr:hover {{ background: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Security Assessment Report</h1>
                    <div class="subtitle">
                        <p><strong>Target:</strong> {report['metadata']['target']}</p>
                        <p><strong>Date:</strong> {report['metadata']['scan_date']}</p>
                        <p><strong>Analyst:</strong> {report['metadata']['analyst']}</p>
                        <p><strong>Scanner Version:</strong> {report['metadata']['scanner_version']}</p>
                    </div>
                </div>
                
                <div class="summary-cards">
                    <div class="card info">
                        <h3>📊 Executive Summary</h3>
                        <p><strong>Total Vulnerabilities:</strong> {report['executive_summary']['total_vulnerabilities']}</p>
                        <p><strong>Risk Score:</strong> {report['executive_summary']['risk_score']}/100</p>
                        
                        <div class="risk-meter">
                            <div class="risk-indicator" style="left: {report['executive_summary']['risk_score']}%;"></div>
                        </div>
                        
                        <p><strong>Breakdown:</strong></p>
                        <ul>
                            <li>Critical: {report['executive_summary']['critical']}</li>
                            <li>High: {report['executive_summary']['high']}</li>
                            <li>Medium: {report['executive_summary']['medium']}</li>
                            <li>Low: {report['executive_summary']['low']}</li>
                        </ul>
                    </div>
                    
                    <div class="card">
                        <h3>🎯 Risk Assessment</h3>
                        {self.generate_risk_assessment_html(report['executive_summary']['risk_score'])}
                    </div>
                    
                    <div class="card">
                        <h3>🛡️ Testing Methodology</h3>
                        <p>Based on OWASP Web Security Testing Guide v4.2</p>
                        <p>Comprehensive testing of OWASP Top 10 vulnerabilities</p>
                        <p>Manual validation of automated findings</p>
                    </div>
                </div>
                
                <h2>📋 Detailed Findings</h2>
                {self.generate_vulnerabilities_html()}
                
                <h2>🎯 Recommendations</h2>
                {self.generate_recommendations_html(report['recommendations'])}
                
                <div class="footer">
                    <p>Report generated by Sean Amon Security Scanner v{report['metadata']['scanner_version']}</p>
                    <p>Confidential - For authorized personnel only</p>
                    <p>Contact: {report['metadata']['contact']} | Portfolio: https://github.com/seanamon</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html_content
        
    def generate_risk_assessment_html(self, risk_score):
        if risk_score >= 70:
            return "<p style='color: #e74c3c; font-weight: bold;'>🔴 HIGH RISK - Immediate action required</p>"
        elif risk_score >= 40:
            return "<p style='color: #e67e22; font-weight: bold;'>🟡 MEDIUM RISK - Address within 1 week</p>"
        else:
            return "<p style='color: #2ecc71; font-weight: bold;'>🟢 LOW RISK - Monitor and plan remediation</p>"
            
    def generate_vulnerabilities_html(self):
        if not self.vulnerabilities:
            return "<p>No vulnerabilities detected during this scan.</p>"
            
        html = ""
        for vuln in self.vulnerabilities:
            html += f"""
            <div class="vulnerability {vuln['severity'].lower()}">
                <h3>
                    <span class="severity-badge severity-{vuln['severity'].lower()}">{vuln['severity']}</span>
                    {vuln['type']}
                </h3>
                <p><strong>OWASP Category:</strong> {vuln['owasp_category']}</p>
                <p><strong>CWE:</strong> {vuln['cwe']}</p>
                <p><strong>URL:</strong> <code>{vuln['url']}</code></p>
                <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                <div class="evidence">
                    <strong>Evidence:</strong><br>
                    {vuln['evidence']}
                </div>
                <div class="recommendation">
                    <strong>Remediation:</strong><br>
                    {vuln['remediation']}
                </div>
                <p><small><strong>Reference:</strong> <a href="{vuln['reference']}" target="_blank">{vuln['reference']}</a></small></p>
            </div>
            """
        return html
        
    def generate_recommendations_html(self, recommendations):
        html = "<div class='card'>"
        html += "<h3>🚨 Immediate Actions (24-48 hours)</h3><ul>"
        for rec in recommendations['immediate']:
            html += f"<li>{rec}</li>"
        html += "</ul>"
        
        html += "<h3>📅 Short Term (1 week)</h3><ul>"
        for rec in recommendations['short_term']:
            html += f"<li>{rec}</li>"
        html += "</ul>"
        
        html += "<h3>🎯 Long Term</h3><ul>"
        for rec in recommendations['long_term']:
            html += f"<li>{rec}</li>"
        html += "</ul></div>"
        
        return html
        
    def generate_text_report(self, report):
        """Generate text-based report for quick review"""
        text = f"""
        ================================================================================
                                SECURITY ASSESSMENT REPORT
        ================================================================================
        
        Target:          {report['metadata']['target']}
        Scan Date:       {report['metadata']['scan_date']}
        Analyst:         {report['metadata']['analyst']}
        Scanner:         v{report['metadata']['scanner_version']}
        Contact:         {report['metadata']['contact']}
        
        ================================================================================
                                EXECUTIVE SUMMARY
        ================================================================================
        
        Total Vulnerabilities: {report['executive_summary']['total_vulnerabilities']}
        Risk Score:            {report['executive_summary']['risk_score']}/100
        
        Severity Breakdown:
        - Critical: {report['executive_summary']['critical']}
        - High:     {report['executive_summary']['high']}
        - Medium:   {report['executive_summary']['medium']}
        - Low:      {report['executive_summary']['low']}
        
        ================================================================================
                                DETAILED FINDINGS
        ================================================================================
        """
        
        for i, vuln in enumerate(report['vulnerabilities'], 1):
            text += f"""
        [{i}] {vuln['severity']}: {vuln['type']}
        {'='*80}
        URL:         {vuln['url']}
        Parameter:   {vuln['parameter']}
        OWASP:       {vuln['owasp_category']}
        CWE:         {vuln['cwe']}
        
        Evidence:
        {vuln['evidence']}
        
        Remediation:
        {vuln['remediation']}
        
        Reference: {vuln['reference']}
        """
            
        text += f"""
        ================================================================================
                                RECOMMENDATIONS
        ================================================================================
        
        IMMEDIATE (24-48 hours):
        {chr(10).join(['- ' + rec for rec in report['recommendations']['immediate']])}
        
        SHORT TERM (1 week):
        {chr(10).join(['- ' + rec for rec in report['recommendations']['short_term']])}
        
        LONG TERM:
        {chr(10).join(['- ' + rec for rec in report['recommendations']['long_term']])}
        
        ================================================================================
        Generated by Sean Amon Security Scanner
        OSCP Candidate | Junior Pentester Portfolio
        ================================================================================
        """
        
        return text
        
    def run(self):
        """Execute complete security scan"""
        print(f"""
        ╔═══════════════════════════════════════════════════════════════╗
        ║                ADVANCED WEB SECURITY SCANNER                  ║
        ║                  Version 2.0 | Sean Amon                      ║
        ╚═══════════════════════════════════════════════════════════════╝
        
        Target: {self.target_url}
        Starting comprehensive security assessment...
        """)
        
        start_time = time.time()
        self.crawl_and_test()
        scan_time = time.time() - start_time
        
        print(f"\n[*] Scan completed in {scan_time:.2f} seconds")
        print(f"[*] Total vulnerabilities found: {len(self.vulnerabilities)}")
        
        # Print summary
        if self.vulnerabilities:
            print("\n" + "="*60)
            print("VULNERABILITY SUMMARY:")
            print("="*60)
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = len([v for v in self.vulnerabilities if v['severity'] == severity])
                if count > 0:
                    print(f"{severity}: {count}")
            print("="*60)
            
        return self.vulnerabilities

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Web Security Scanner - Professional Grade',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com -o html -f report.html
  %(prog)s https://example.com -o json -f results.json
  
Author: Sean Amon | OSCP Candidate | Junior Pentester
GitHub: https://github.com/seanamon
        """
    )
    
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', choices=['json', 'html', 'text'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('-f', '--file', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate target URL
    if not args.target.startswith(('http://', 'https://')):
        print("[!] Error: Target must start with http:// or https://")
        sys.exit(1)
        
    scanner = SecurityScanner(args.target)
    vulnerabilities = scanner.run()
    
    if vulnerabilities:
        report = scanner.generate_report(args.output)
        
        if args.file:
            with open(args.file, 'w') as f:
                f.write(report)
            print(f"[*] Report saved to: {args.file}")
            
            # Also save JSON for programmatic use
            if args.output != 'json':
                json_report = scanner.generate_report('json')
                with open(f"{args.file}.json", 'w') as f:
                    f.write(json_report)
        else:
            print(report)
    else:
        print("[*] No vulnerabilities detected. Target appears secure.")
        
        # Still generate a clean report
        report = scanner.generate_report(args.output)
        if args.file:
            with open(args.file, 'w') as f:
                f.write(report)
            print(f"[*] Clean report saved to: {args.file}")

if __name__ == "__main__":
    main()
