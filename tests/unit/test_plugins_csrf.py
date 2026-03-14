"""Unit tests for CSRFCheck plugin."""
import pytest
from webvulnscanner.plugins.csrf import CSRFCheck


@pytest.fixture
def csrf_check() -> CSRFCheck:
    return CSRFCheck()


HTML_FORM_NO_TOKEN = """
<html><body>
  <form action="/login" method="POST">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <button type="submit">Login</button>
  </form>
</body></html>
"""

HTML_FORM_WITH_CSRF = """
<html><body>
  <form action="/login" method="POST">
    <input type="hidden" name="csrf_token" value="abc123" />
    <input type="text" name="username" />
    <button type="submit">Login</button>
  </form>
</body></html>
"""

HTML_FORM_WITH_NONCE = """
<html><body>
  <form action="/post" method="POST">
    <input type="hidden" name="nonce" value="xyz789" />
    <textarea name="body"></textarea>
    <button type="submit">Submit</button>
  </form>
</body></html>
"""

HTML_FORM_WITH_AUTHENTICITY = """
<html><body>
  <form action="/vote" method="POST">
    <input type="hidden" name="authenticity_token" value="rails_token" />
    <button type="submit">Vote</button>
  </form>
</body></html>
"""

HTML_NO_FORMS = "<html><body><p>No forms here</p></body></html>"


class TestCSRFCheck:

    def test_name_property(self, csrf_check: CSRFCheck):
        assert csrf_check.name == "CSRF Heuristic"

    def test_name_is_property_not_class_attr(self):
        assert isinstance(type(CSRFCheck()).name, property)

    async def test_no_html_returns_empty(self, csrf_check: CSRFCheck, mock_session):
        result = await csrf_check.check(mock_session, "http://example.com", html="")
        assert result == []

    async def test_no_forms_returns_empty(self, csrf_check: CSRFCheck, mock_session):
        result = await csrf_check.check(mock_session, "http://example.com", html=HTML_NO_FORMS)
        assert result == []

    async def test_form_without_token_detected(self, csrf_check: CSRFCheck, mock_session):
        result = await csrf_check.check(mock_session, "http://example.com/login", html=HTML_FORM_NO_TOKEN)
        assert len(result) == 1
        assert result[0].type == "Potential CSRF"
        assert "Form without CSRF token" in result[0].evidence
        assert result[0].severity == "Low"

    async def test_form_with_csrf_token_not_detected(self, csrf_check: CSRFCheck, mock_session):
        result = await csrf_check.check(mock_session, "http://example.com/login", html=HTML_FORM_WITH_CSRF)
        assert result == []

    async def test_form_with_nonce_not_detected(self, csrf_check: CSRFCheck, mock_session):
        result = await csrf_check.check(mock_session, "http://example.com/post", html=HTML_FORM_WITH_NONCE)
        assert result == []

    async def test_form_with_authenticity_token_not_detected(self, csrf_check: CSRFCheck, mock_session):
        """BUG fix regression: 'authenticity' should be recognized as a CSRF token."""
        result = await csrf_check.check(mock_session, "http://example.com/vote", html=HTML_FORM_WITH_AUTHENTICITY)
        assert result == []
