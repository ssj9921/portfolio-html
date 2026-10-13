import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_public import CSP, SecurityError, validate_html, validate_repository

POLICY = {"approved_external_links": ["https://example.com/public"], "approved_contacts": []}


def page(body="", style=""):
    return ('<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="referrer" content="no-referrer">'
            '<meta http-equiv="Content-Security-Policy" content="' + CSP + '">'
            '<style>' + style + '</style></head><body>' + body + '</body></html>')


class PublicPolicyTests(unittest.TestCase):
    def test_static_page_and_approved_navigation(self):
        validate_html(page('<a href="https://example.com/public" target="_blank" rel="noopener noreferrer">Open</a>'), POLICY)

    def test_script_executable_attributes_and_external_resources_fail(self):
        cases = ['<script>alert(1)</script>', '<div onclick="alert(1)">x</div>',
                 '<a href="java&#115;cript:alert(1)">x</a>', '<img src="https://example.com/a.png">',
                 '<iframe></iframe>', '<form></form>', '<svg><foreignObject>x</foreignObject></svg>',
                 '<a href="https://example.com/public" target="_blank">x</a>']
        for body in cases:
            with self.subTest(body=body), self.assertRaises(SecurityError):
                validate_html(page(body), POLICY)

    def test_hidden_private_sources_contacts_and_secrets_fail(self):
        cases = ['<!-- https://' + 'app' + '.notion.com/p/example -->',
                 '<div hidden>' + 'ghp' + '_' + 'x' * 30 + '</div>',
                 '<p>' + 'person' + '@example.com</p>']
        for body in cases:
            with self.subTest(body=body), self.assertRaises(SecurityError):
                validate_html(page(body), POLICY)

    def test_encoded_css_imports_and_urls_fail(self):
        for style in ['@import "https://example.com/x.css";', r'@im\70ort "x";',
                      r'p{background:u\72l("https://example.com/x")}']:
            with self.subTest(style=style), self.assertRaises(SecurityError):
                validate_html(page(style=style), POLICY)

    def test_policy_metadata_cannot_be_removed_or_weakened(self):
        good = page()
        for content in [good.replace("script-src 'none'", "script-src 'unsafe-inline'"),
                        good.replace('content="no-referrer"', 'content="origin"'),
                        good.replace('<meta charset="utf-8">', '')]:
            with self.subTest(content=content), self.assertRaises(SecurityError):
                validate_html(content, POLICY)

    def test_unregistered_files_and_changed_html_stop_repository_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "docs").mkdir()
            data = page().encode()
            (root / "docs/index.html").write_bytes(data)
            (root / "policy.json").write_text(json.dumps(POLICY), encoding="utf-8")
            (root / "docs/catalog.json").write_text(json.dumps({"pages": [{"path": "index.html", "sha256": hashlib.sha256(data).hexdigest()}]}), encoding="utf-8")
            self.assertTrue(validate_repository(root)["valid"])
            extra = root / ("private" + ".md")
            extra.write_text("Private draft", encoding="utf-8")
            with self.assertRaises(SecurityError):
                validate_repository(root)
            extra.unlink()
            (root / "docs/index.html").write_text(page("Changed"), encoding="utf-8")
            with self.assertRaises(SecurityError):
                validate_repository(root)

    def test_relative_links_cannot_escape_site(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            site = root / "docs"
            site.mkdir()
            (root / "outside.html").write_text(page(), encoding="utf-8")
            with self.assertRaises(SecurityError):
                validate_html(page('<a href="../outside.html">x</a>'), POLICY, site / "index.html", site)


if __name__ == "__main__":
    unittest.main()
