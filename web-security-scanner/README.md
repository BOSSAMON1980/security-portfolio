# 🚀 Advanced Web Security Scanner

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-scanner-orange)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)

A professional-grade web application security scanner built for penetration testers and security researchers. This tool automates the detection of OWASP Top 10 vulnerabilities with comprehensive reporting capabilities.

## ✨ Features

### 🔍 Vulnerability Detection
- **SQL Injection** - Multiple payload testing with error-based detection
- **Cross-Site Scripting (XSS)** - Reflected XSS testing with various payloads
- **Insecure Direct Object References (IDOR)** - Access control testing
- **Security Header Analysis** - Missing security headers detection
- **CORS Misconfiguration** - Insecure CORS policy testing
- **Information Disclosure** - Sensitive file/directory detection

### 📊 Professional Reporting
- **JSON Reports** - Machine-readable format for integration
- **HTML Reports** - Beautiful, professional-grade HTML output
- **Text Reports** - Clean console-friendly output
- **Executive Summary** - Risk scoring and severity breakdown
- **Technical Details** - Evidence, CWE mapping, OWASP categorization
- **Actionable Recommendations** - Priority-based remediation guidance

### ⚡ Performance
- **Multi-threaded Scanning** - Concurrent vulnerability testing
- **Intelligent Crawling** - Smart endpoint discovery
- **Configurable Timeouts** - Adjustable for different network conditions
- **Error Handling** - Robust exception management

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/seanamon/web-security-scanner.git
cd web-security-scanner

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python scanner.py https://example.com
