from .xss import XSSCheck
from .sqli import SQLiCheck
from .headers import SecurityHeadersCheck
from .secrets import SecretsCheck
from .csrf import CSRFCheck
from .ssrf import SSRFCheck

# List of available plugins classes
ALL_PLUGINS = [
    XSSCheck,
    SQLiCheck,
    SecurityHeadersCheck,
    SecretsCheck,
    CSRFCheck,
    SSRFCheck
]
