import pytest
import urllib.parse
from webvulnscanner.utils.encoder import WafEncoder

def test_double_url_encode():
    assert WafEncoder.double_url_encode("<script>") == "%253Cscript%253E"

def test_hex_encode():
    assert WafEncoder.hex_encode("admin") == "%61%64%6d%69%6e"

def test_sqli_tamper():
    payload = "UNION SELECT"
    tampered = WafEncoder.sqli_tamper(payload)
    assert tampered != payload
    assert "UNION" in tampered and "SELECT" in tampered
    assert any(c in tampered for c in ['/**/', '%0a', '%0b', '%0c', '%0d', '%09'])

def test_apply_random_mutation():
    payload = "UNION SELECT"
    mutated = WafEncoder.apply_random_mutation(payload, context="sqli")
    assert mutated == payload or "UNION" in mutated # Puede quedar intacto (JSON-safe) o aplicar sqli_tamper
