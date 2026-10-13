"""Fail-closed checks for the dedicated public HTML export (standard library only)."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

CSP = "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"
SECRET = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:ntn_|secret_)[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:api[_-]?key|password|access[_-]?token)\s*[:=]\s*[\"']?[^\s\"']{12,}", re.I)
PRIVATE = re.compile(r"app\.notion\.com|(?:www\.)?notion\.so/|notion-file-block\x3a|collection\x3a//|X-Amz\x2d|[A-Z]:[\\/]Users[\\/]|file\x3a//|(?:localhost|127\.0\.0\.1)(?=[:/])", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"\b01[016789][- ]?\d{3,4}[- ]?\d{4}\b")
PUBLIC_FILES = {".gitignore", ".gitattributes", "AGENTS.md", "README.md", "SECURITY.md", "policy.json",
                ".github/workflows/deploy.yml", ".githooks/pre-push",
                "tools/check_public.py", "tests/test_public.py", "docs/.nojekyll",
                "docs/index.html", "docs/catalog.json"}
COMPONENT_PATH = re.compile(r"docs/components/[a-z0-9][a-z0-9-]*/v\d+\.\d+\.\d+/index\.html")


class SecurityError(ValueError):
    pass


def check_text(text):
    # Include comments, hidden markup and encoded text in disclosure checks.
    import html
    decoded = unquote(html.unescape(text))
    if SECRET.search(decoded):
        raise SecurityError("Potential credential; do not publish")
    if PRIVATE.search(decoded):
        raise SecurityError("Private reference or local address; do not publish")


def css_check(text):
    text = re.sub(r"/\*[\s\S]*?\*/", "", text)
    text = re.sub(r"\\([0-9a-fA-F]{1,6})\s?", lambda m: chr(int(m[1], 16)), text)
    text = re.sub(r"\\(.)", r"\1", text)
    if re.search(r"@import\b|\bexpression\s*\(|url\s*\(", text, re.I):
        raise SecurityError("External or executable CSS assets are prohibited")


def validate_html(text, policy, path=None, site=None):
    check_text(text)
    for value in EMAIL.findall(text) + PHONE.findall(text):
        if value not in policy.get("approved_contacts", []):
            raise SecurityError("Unapproved personal contact information")

    class StaticPage(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.styles = False
            self.csp = False
            self.referrer = False
            self.charset = False
            self.viewport = False

        def handle_starttag(self, tag, attrs):
            names = [name for name, _ in attrs]
            if len(names) != len(set(names)):
                raise SecurityError("Duplicate HTML attributes")
            values = dict(attrs)
            if tag in {"script", "iframe", "object", "embed", "base", "link", "form", "foreignobject"}:
                raise SecurityError("Scripts, frames, forms and external resources are prohibited")
            for name, value in attrs:
                if name.startswith("on") or name in {"srcdoc", "src", "srcset", "poster", "data", "xlink:href"}:
                    raise SecurityError("Executable attributes and remote resources are prohibited")
                if name == "style":
                    css_check(value or "")
            if tag == "meta":
                equiv = (values.get("http-equiv") or "").lower()
                if equiv and equiv != "content-security-policy":
                    raise SecurityError("Meta refresh and other HTTP-equivalent directives are prohibited")
                if equiv == "content-security-policy":
                    if values.get("content") != CSP:
                        raise SecurityError("Missing or weakened static-page CSP")
                    self.csp = True
                if values.get("name") == "referrer" and values.get("content") == "no-referrer":
                    self.referrer = True
                if values.get("charset", "").lower() == "utf-8":
                    self.charset = True
                if values.get("name") == "viewport":
                    self.viewport = True
            if tag == "a":
                href = values.get("href") or ""
                parsed = urlsplit(href)
                if not href or "\\" in href or re.search(r"[\x00-\x20]", href):
                    raise SecurityError("Unsafe or empty hyperlink")
                if parsed.scheme or parsed.netloc:
                    if parsed.scheme != "https" or href not in policy["approved_external_links"]:
                        raise SecurityError("Hyperlink is outside the approved public URL list")
                    if values.get("target") == "_blank":
                        rel = set((values.get("rel") or "").split())
                        if not {"noopener", "noreferrer"} <= rel:
                            raise SecurityError("New-window link must use noopener and noreferrer")
                elif not href.startswith("#"):
                    if href.startswith("/") or parsed.query:
                        raise SecurityError("Use relative links without query parameters")
                    if path and site:
                        target = (path.parent / unquote(parsed.path)).resolve()
                        if not target.is_relative_to(site.resolve()) or not target.is_file():
                            raise SecurityError("Relative hyperlink escapes the published site or is missing")
            if tag == "style":
                if not self.csp:
                    raise SecurityError("CSP must precede CSS and visible content")
                self.styles = True
            if tag == "body" and not self.csp:
                raise SecurityError("CSP must be in the head before the body")

        def handle_startendtag(self, tag, attrs):
            self.handle_starttag(tag, attrs)

        def handle_endtag(self, tag):
            if tag == "style":
                self.styles = False

        def handle_data(self, text):
            if self.styles:
                css_check(text)

    page = StaticPage()
    page.feed(text)
    page.close()
    if not all((page.csp, page.referrer, page.charset, page.viewport)):
        raise SecurityError("Page requires CSP, no-referrer, UTF-8 and viewport metadata")


def validate_repository(root):
    root = Path(root).resolve()
    policy = json.loads((root / "policy.json").read_text(encoding="utf-8"))
    files = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if any(part in {".git", "__pycache__"} for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            raise SecurityError("Symbolic links must never enter the public export")
        if not path.is_file():
            continue
        if relative not in PUBLIC_FILES and not COMPONENT_PATH.fullmatch(relative):
            raise SecurityError("Unexpected file in public export: " + relative)
        if path.stat().st_size > 250 * 1024:
            raise SecurityError("Public text file exceeds the 250 KiB limit")
        text = path.read_text(encoding="utf-8")
        check_text(text)
        if path.suffix == ".html":
            validate_html(text, policy, path, root / "docs")
        files.append(relative)
    catalog = json.loads((root / "docs/catalog.json").read_text(encoding="utf-8"))
    entries = catalog["pages"]
    if len({p["path"] for p in entries}) != len(entries):
        raise SecurityError("Duplicate catalog routes")
    html_files = {name.removeprefix("docs/") for name in files if name.endswith(".html")}
    if {p["path"] for p in entries} != html_files:
        raise SecurityError("Catalog must list every public HTML file exactly once")
    for entry in entries:
        data = (root / "docs" / entry["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise SecurityError("Catalog hash differs from public HTML")
    return {"files": len(files), "html_pages": len(entries), "valid": True}


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = cli.parse_args()
    try:
        print(json.dumps(validate_repository(args.root), ensure_ascii=False))
    except (SecurityError, ValueError, OSError) as exc:
        raise SystemExit("Public export stopped: " + str(exc))
