# Bug Finder - Security Vulnerability Scanner

An automated security vulnerability scanner for web applications and APIs.

## Features

- Automated vulnerability scanning
- Common security issue detection
- XSS detection
- SQL injection testing
- CSRF vulnerability checking
- Security headers analysis
- Detailed vulnerability reports
- Remediation suggestions

## Tech Stack

- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Node.js, Express
- **Database**: SQLite
- **Scanner**: Custom security testing engine

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set up environment variables
4. Run the application:
   ```bash
   npm start
   ```

## Quick Start

Use the provided batch file:
```bash
run.bat
```

## Scanning Capabilities

- **XSS (Cross-Site Scripting)**: Detects reflected and stored XSS vulnerabilities
- **SQL Injection**: Tests for SQL injection vulnerabilities
- **CSRF**: Checks for Cross-Site Request Forgery protection
- **Security Headers**: Analyzes HTTP security headers
- **Authentication**: Tests authentication mechanisms
- **Authorization**: Checks for broken access control

## Usage

1. Enter the target URL
2. Select scan type (Quick/Full)
3. Start the scan
4. View detailed results
5. Export reports

## Environment Variables

```
PORT=3000
DB_PATH=./bugfinder.db
MAX_SCAN_DEPTH=3
TIMEOUT=30000
```

## Security Note

This tool is for educational and authorized security testing only. Always obtain permission before scanning any website or application.

## License

MIT


## Recent Updates

- **2026-08-05**: feat: Add configuration examples

- **2026-08-05**: docs: Add testing documentation

- **2026-08-05**: feat: Add configuration examples

- **2026-08-05**: docs: Add testing documentation

- **2026-05-13**: Update dependencies

- **2026-05-30**: Fix bugs

- **2026-06-05**: Update documentation

- **2026-06-12**: Add tests

- **2026-06-12**: Update README
