from dataclasses import dataclass, field
from typing import List, Optional

# Constants & Regex
DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": "WebVulnScanner/2.0 (Async)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}

# XSS Payloads for testing reflection
XSS_PAYLOADS: List[str] = [
    '<script>alert(1)</script>',
    '" onmouseover=alert(1) x="',
    'javascript:alert(1)',
]

SQL_ERRORS = [
    'you have an error in your sql syntax', 'warning: mysql',
    'unclosed quotation mark', 'quoted string not properly terminated'
]

# Secret Patterns with improved precision
REGEX_SECRETS: dict[str, str] = {
    'AWS Access Key': r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', # Simplified for example, better to use specific prefixes like AKIA
    'AWS API Key': r'AKIA[0-9A-Z]{16}',
    'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
    'Generic Token': r'(api_key|auth_token|access_token|secret_key)\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{20,})[\"\']',
    'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
    'Private Key': r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PRIVATE)\s+KEY-----',
}

REGEX_ENDPOINTS = r'["\'](\/[a-zA-Z0-9_./-]+)["\']'

SENSITIVE_FILES = [
    '.env', '.git/HEAD', '.svn/entries', '.DS_Store',
    'wp-config.php.bak', 'config.php.bak', 'backup.zip', 'database.sql',
    'package-lock.json', 'composer.lock'
]

SECURITY_HEADERS = {
    'Content-Security-Policy': 'Missing CSP',
    'X-Frame-Options': 'Missing X-Frame-Options (Clickjacking Risk)',
    'Strict-Transport-Security': 'Missing HSTS',
    'X-Content-Type-Options': 'Missing X-Content-Type-Options'
}

@dataclass
class ScanConfig:
    start_url: str
    max_pages: int = 100
    concurrency: int = 20
    checks: List[str] = field(default_factory=list)
    allow_intrusive: bool = False
    authorized: bool = False
    dir_bruteforce: bool = False
    wordlist: Optional[str] = None
