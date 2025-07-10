# Bug Bounty Scanner Framework

An advanced Python-based security scanner designed to identify common web application vulnerabilities. This tool is built for ethical security testing and bug bounty hunting.

## 🚀 Features

### Core Vulnerability Scans
- **Cross-Site Scripting (XSS)** - Detects reflected XSS vulnerabilities
- **SQL Injection** - Identifies SQL injection points with error-based detection
- **Server-Side Request Forgery (SSRF)** - Tests for SSRF vulnerabilities
- **Open Redirect** - Finds open redirect vulnerabilities
- **Information Disclosure** - Scans for exposed sensitive files and data

### Security Configuration Checks
- **Security Headers Analysis** - Checks for missing security headers
- **CORS Misconfiguration** - Identifies CORS policy issues
- **Sensitive File Exposure** - Scans for exposed configuration files, backups, and secrets

### Advanced Features
- **Multi-threaded Scanning** - Concurrent vulnerability testing for faster results
- **Intelligent Crawling** - Automatically discovers URLs with parameters
- **Comprehensive Reporting** - Generates detailed JSON reports with severity ratings
- **Extensible Architecture** - Easy to add new vulnerability checks

## 📋 Requirements

- Python 3.6+
- Required packages:
  ```
  requests
  beautifulsoup4
  ```

## 🛠️ Installation

1. Clone or download the repository:
   ```bash
   git clone <repository-url>
   cd bug-bounty-scanner
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   
   Or install manually:
   ```bash
   pip install requests beautifulsoup4
   ```

## 🎯 Usage

### Basic Usage

Run the scanner interactively:
```bash
python bugscanner.py
```

### Programmatic Usage

```python
from bugscanner import BugBountyScanner

# Initialize scanner
scanner = BugBountyScanner("https://example.com", threads=10)

# Run comprehensive scan
report = scanner.run_scan()

# Access results
print(f"Found {report['total_vulnerabilities']} vulnerabilities")
```

### Individual Vulnerability Scans

```python
# Test specific vulnerability types
xss_results = scanner.scan_xss("https://example.com/search?q=test")
sql_results = scanner.scan_sql_injection("https://example.com/login?user=admin")
ssrf_results = scanner.scan_ssrf("https://example.com/fetch?url=http://example.com")
```

## 📊 Vulnerability Detection

### XSS (Cross-Site Scripting)
- Tests multiple XSS payloads including script tags, event handlers, and SVG vectors
- Checks for payload reflection in response content
- **Severity**: High

### SQL Injection
- Uses time-tested SQL injection payloads
- Detects database errors in responses
- Supports multiple database types (MySQL, PostgreSQL, MSSQL, Oracle)
- **Severity**: Critical

### SSRF (Server-Side Request Forgery)
- Tests internal network access (localhost, 127.0.0.1)
- Checks cloud metadata endpoints (AWS, GCP)
- Monitors response times for blind SSRF detection
- **Severity**: High

### Open Redirect
- Tests various redirect bypass techniques
- Monitors HTTP redirect responses
- **Severity**: Medium

### Security Headers
Checks for missing security headers:
- `X-Frame-Options`
- `X-Content-Type-Options`
- `X-XSS-Protection`
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `Referrer-Policy`
- `Permissions-Policy`
- **Severity**: Low

### Information Disclosure
Scans for sensitive files:
- `.git/config`
- `.env`
- `config.php`
- `phpinfo.php`
- Database dumps
- And more...
- **Severity**: Medium to High

## 📈 Report Generation

The scanner generates comprehensive JSON reports containing:

```json
{
  "scan_date": "2024-01-01T12:00:00",
  "target": "https://example.com",
  "total_vulnerabilities": 5,
  "severity_breakdown": {
    "Critical": 1,
    "High": 2,
    "Medium": 1,
    "Low": 1
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "Critical",
      "url": "https://example.com/login?user=admin",
      "parameter": "user",
      "payload": "' OR '1'='1",
      "evidence": "SQL error detected: MySQL syntax"
    }
  ]
}
```

## ⚙️ Configuration

### Scanner Options

```python
scanner = BugBountyScanner(
    target_url="https://example.com",
    threads=10  # Number of concurrent threads
)
```

### Custom Headers

The scanner uses realistic browser headers by default:
```python
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}
```

## 🔧 Extending the Scanner

### Adding New Vulnerability Checks

```python
def scan_custom_vulnerability(self, url):
    """Custom vulnerability scanner"""
    results = []
    
    # Your scanning logic here
    
    return results
```

### Advanced Scanner Class

The framework includes an `AdvancedScanner` class with placeholders for:
- XML External Entity (XXE) attacks
- Server-Side Template Injection (SSTI)
- Path Traversal attacks

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing only. 

- Only use this scanner on systems you own or have explicit permission to test
- Unauthorized scanning of systems may violate laws and regulations
- The authors are not responsible for any misuse of this tool
- Always follow responsible disclosure practices when reporting vulnerabilities

## 🛡️ Ethical Usage Guidelines

1. **Get Permission**: Always obtain written authorization before scanning
2. **Respect Rate Limits**: Don't overwhelm target systems
3. **Report Responsibly**: Follow proper disclosure procedures
4. **Stay Legal**: Comply with all applicable laws and regulations
5. **Be Professional**: Maintain ethical standards in security research

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Areas for Contribution
- Additional vulnerability scanners
- Improved detection techniques
- Better reporting formats
- Performance optimizations
- Documentation improvements

## 🔍 Roadmap

- [ ] Web interface for easier usage
- [ ] Database integration for result storage
- [ ] Custom payload management
- [ ] Integration with popular security tools
- [ ] Machine learning-based vulnerability detection
- [ ] Mobile application security testing

## 📞 Support

For questions, issues, or contributions:
- Open an issue on GitHub
- Follow responsible disclosure for security issues

## 🏆 Acknowledgments

- OWASP for vulnerability classification and testing methodologies
- Security research community for payload development
- Open source contributors and maintainers

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.
