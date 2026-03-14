from dataclasses import dataclass, field
from typing import List, Optional

# Constants & Regex
DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": "WebVulnScanner/2.0 (Async)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}

# Secret Patterns — ordered from most specific to least specific to reduce false positives.
# NOTE: The generic 20-char uppercase pattern was removed because it generates
# massive false positives (matches any 20-char uppercase string). The AKIA prefix
# pattern already covers AWS Access Keys correctly.
REGEX_SECRETS: dict[str, str] = {
    'AWS API Key': r'AKIA[0-9A-Z]{16}',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Generic Token': r'(?:api_key|auth_token|access_token|secret_key)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
    'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
    'Private Key': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |)PRIVATE KEY-----',
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
