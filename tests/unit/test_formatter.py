"""Unit tests for ReportGenerator (formatter)."""
import json
import pytest
from unittest.mock import MagicMock
from webvulnscanner.reporting.formatter import ReportGenerator
from webvulnscanner.models.vulnerability import Vulnerability


def _make_scanner(vulns=None, visited=None, js_files=None):
    """Helper: creates a minimal mock AsyncScanner."""
    scanner = MagicMock()
    scanner.vulnerabilities = vulns or []
    scanner.visited = visited or set()
    scanner.js_files_scanned = js_files or set()
    return scanner


class TestReportGeneratorPrepareResults:

    def test_empty_scanner_returns_valid_structure(self):
        scanner = _make_scanner()
        data = ReportGenerator.prepare_results("http://example.com", scanner)
        assert "meta" in data
        assert "crawl" in data
        assert "checks" in data

    def test_meta_contains_target(self):
        scanner = _make_scanner()
        data = ReportGenerator.prepare_results("http://target.com", scanner)
        assert data["meta"]["target"] == "http://target.com"

    def test_meta_contains_timestamp(self):
        """BUG-13 regression: timestamp must be in the meta block."""
        scanner = _make_scanner()
        data = ReportGenerator.prepare_results("http://example.com", scanner)
        assert "timestamp" in data["meta"]
        # Should be a valid ISO timestamp (timezone-aware: contains '+00:00' or ends with 'Z')
        ts = data["meta"]["timestamp"]
        assert ts and len(ts) > 10  # at minimum a date string

    def test_crawl_pages_count(self):
        scanner = _make_scanner(visited={"http://a.com", "http://b.com"})
        data = ReportGenerator.prepare_results("http://example.com", scanner)
        assert data["crawl"]["pages_count"] == 2

    def test_vulnerability_categorized_correctly(self):
        vuln = Vulnerability(type="Reflected XSS", url="http://x.com", severity="High")
        scanner = _make_scanner(vulns=[vuln])
        data = ReportGenerator.prepare_results("http://x.com", scanner)
        assert "xss" in data["checks"]
        assert len(data["checks"]["xss"]) == 1

    def test_severity_included_in_checks(self):
        """BUG-13 regression: severity must appear in the checks data."""
        vuln = Vulnerability(type="SQLi Error-Based", url="http://x.com", severity="Critical")
        scanner = _make_scanner(vulns=[vuln])
        data = ReportGenerator.prepare_results("http://x.com", scanner)
        items = data["checks"].get("sqli", [])
        assert items[0]["severity"] == "Critical"


class TestReportGeneratorJSON:

    def test_generate_json_is_valid(self):
        scanner = _make_scanner()
        data = ReportGenerator.prepare_results("http://example.com", scanner)
        json_str = ReportGenerator.generate_json(data)
        parsed = json.loads(json_str)
        assert parsed["meta"]["target"] == "http://example.com"

    def test_generate_json_indented(self):
        scanner = _make_scanner()
        data = ReportGenerator.prepare_results("http://example.com", scanner)
        json_str = ReportGenerator.generate_json(data)
        # Indented JSON has newlines
        assert "\n" in json_str


class TestReportGeneratorMarkdown:

    def test_generate_markdown_has_heading(self):
        scanner = _make_scanner()
        data = ReportGenerator.prepare_results("http://example.com", scanner)
        md = ReportGenerator.generate_markdown(data)
        assert "# Reporte de Vulnerabilidades" in md

    def test_generate_markdown_no_vulns_note(self):
        scanner = _make_scanner()
        data = ReportGenerator.prepare_results("http://example.com", scanner)
        md = ReportGenerator.generate_markdown(data)
        assert "No se encontraron vulnerabilidades" in md

    def test_generate_markdown_includes_severity(self):
        """BUG-13 regression: severity must appear in Markdown output."""
        vuln = Vulnerability(type="Reflected XSS", url="http://x.com", severity="High")
        scanner = _make_scanner(vulns=[vuln])
        data = ReportGenerator.prepare_results("http://x.com", scanner)
        md = ReportGenerator.generate_markdown(data)
        assert "High" in md

    def test_generate_markdown_includes_vuln_type(self):
        vuln = Vulnerability(type="SQLi Error-Based", url="http://x.com", severity="Critical")
        scanner = _make_scanner(vulns=[vuln])
        data = ReportGenerator.prepare_results("http://x.com", scanner)
        md = ReportGenerator.generate_markdown(data)
        assert "SQLi Error-Based" in md
