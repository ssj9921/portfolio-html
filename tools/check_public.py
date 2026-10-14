"""Fail-closed checks for the dedicated public HTML export (standard library only)."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import re
import subprocess
import posixpath
import struct
import zlib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

CSP = "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"
SECRET = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:ntn_|secret_)[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:api[_-]?key|password|access[_-]?token)\s*[:=]\s*[\"']?[^\s\"']{12,}", re.I)
PRIVATE = re.compile(r"app\.notion\.com|(?:www\.)?notion\.so/|notion-file-block\x3a|collection\x3a//|X-Amz\x2d|[A-Z]:[\\/]Users[\\/]|file\x3a//|(?:localhost|127\.0\.0\.1)(?=[:/])", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"(?<![\w+])(?:01[016789][- .]?\d{3,4}[- .]?\d{4}|\+821[016789]\d{7,8})(?!\w)")
PUBLIC_FILES = {".gitignore", ".gitattributes", "AGENTS.md", "README.md", "SECURITY.md", "policy.json",
                ".github/workflows/deploy.yml", ".githooks/pre-push",
                "tools/check_public.py", "tests/test_public.py", "docs/.nojekyll",
                "docs/index.html", "docs/catalog.json"}
COMPONENT_PATH = re.compile(r"docs/components/[a-z0-9][a-z0-9-]*/v\d+\.\d+\.\d+/index\.html")
IMAGE_PATH = re.compile(r"assets/[a-z0-9][a-z0-9-]*/v\d+\.\d+\.\d+/[a-z0-9][a-z0-9-]*\.(?:png|jpg)")
YOUTUBE_EMBED = re.compile(r"https://www\.youtube-nocookie\.com/embed/[A-Za-z0-9_-]{11}")
IFRAME_ATTRIBUTES = {
    "width": "560", "height": "315", "loading": "lazy",
    "referrerpolicy": "strict-origin-when-cross-origin",
    "allow": "autoplay 'none'; encrypted-media; picture-in-picture; fullscreen",
    "sandbox": "allow-scripts allow-same-origin allow-presentation",
    "class": "video-frame",
}


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


WEBFONTS = {
    'chosun-bold': ('ChosunKm', 'https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_20-04@1.0/ChosunKm.woff'),
    'chosun-shin': ('ChosunSm', 'https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_20-04@1.1/ChosunSm.woff'),
}


def font_css(name):
    family, url = WEBFONTS[name]
    return '@font-face{font-family:"'+family+'";src:url("'+url+'") format("woff");font-style:normal;font-weight:400;font-display:swap;}'


def approved_fonts(policy, route):
    approved = policy.get('approved_webfonts', {})
    if not isinstance(approved, dict):
        raise SecurityError('Webfont approvals must map exact page routes')
    for key, names in approved.items():
        if key != 'index.html' and (not isinstance(key,str) or not COMPONENT_PATH.fullmatch('docs/'+key)):
            raise SecurityError('Webfonts require an exact public page route')
        if not isinstance(names,list) or not names or any(n not in WEBFONTS for n in names) or len(names)!=len(set(names)):
            raise SecurityError('Only the two reviewed original WOFF fonts are permitted')
    return approved.get(route, [])


def css_check(text, fonts=()):
    used=[]
    for name in fonts:
        declaration=font_css(name)
        used.extend([name]*text.count(declaration))
        text=text.replace(declaration,'')
    text = re.sub(r"/\*[\s\S]*?\*/", "", text)
    text = re.sub(r"\\([0-9a-fA-F]{1,6})\s?", lambda m: chr(int(m[1], 16)), text)
    text = re.sub(r"\\(.)", r"\1", text)
    if re.search(r"@import\b|@font-face\b|\bexpression\s*\(|url\s*\(", text, re.I):
        raise SecurityError("External or executable CSS assets are prohibited")
    return used


def approved_embeds(policy, route):
    """Only explicit immutable routes may opt into exact privacy-enhanced URLs."""
    approved = policy.get("approved_youtube_embeds", {})
    if not isinstance(approved, dict):
        raise SecurityError("YouTube approvals must map component routes to exact URLs")
    for key, urls in approved.items():
        if not isinstance(key, str) or not COMPONENT_PATH.fullmatch("docs/" + key):
            raise SecurityError("YouTube approvals require an immutable component route")
        if (not isinstance(urls, list) or not urls
                or any(not isinstance(url, str) or not YOUTUBE_EMBED.fullmatch(url) for url in urls)
                or len(urls) != len(set(urls))):
            raise SecurityError("Only exact privacy-enhanced YouTube video URLs are permitted")
        for url in urls:
            if youtube_watch_url(url) not in policy["approved_external_links"]:
                raise SecurityError("Every approved embed requires its approved watch URL")
    return approved.get(route, [])


def youtube_watch_url(url):
    return "https://www.youtube.com/watch?v=" + url.rsplit("/", 1)[1]


def approved_scripts(policy, route):
    approved = policy.get("approved_inline_scripts", {})
    if not isinstance(approved, dict):
        raise SecurityError("Script approvals must map versioned routes to hashes")
    if approved and policy.get("javascript_allowed") is not True:
        raise SecurityError("JavaScript requires explicit policy authorization")
    for key, hashes in approved.items():
        if not isinstance(key, str) or (not COMPONENT_PATH.fullmatch("docs/" + key) and not (key == "index.html" and policy.get("homepage_script_allowed") is True)):
            raise SecurityError("Scripts require an immutable component route")
        if (not isinstance(hashes, list) or not hashes
                or any(not isinstance(h, str) or not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", h) for h in hashes)
                or len(hashes) != len(set(hashes))):
            raise SecurityError("Scripts require unique exact SHA256 hashes")
    return approved.get(route, [])


def script_hash(source):
    return "sha256-" + base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode("ascii")


def approved_images(policy, route=None):
    assets = policy.get('approved_image_assets', {})
    pages = policy.get('approved_page_images', {})
    if not isinstance(assets, dict) or not isinstance(pages, dict):
        raise SecurityError('Image approvals must be exact maps')
    for name, meta in assets.items():
        if not isinstance(name, str) or not IMAGE_PATH.fullmatch(name) or not isinstance(meta, dict):
            raise SecurityError('Images require immutable local asset paths')
        if set(meta) != {'sha256','media_type','width','height'} or not re.fullmatch(r'[0-9a-f]{64}',str(meta['sha256'])):
            raise SecurityError('Images require exact review hashes and dimensions')
        expected = 'image/png' if name.endswith('.png') else 'image/jpeg'
        if meta['media_type'] != expected or any(type(meta[k]) is not int or not 1 <= meta[k] <= 8192 for k in ('width','height')):
            raise SecurityError('Invalid image format or dimensions')
    for name, images in pages.items():
        if (name != 'index.html' and not COMPONENT_PATH.fullmatch('docs/'+name)) or not isinstance(images,list) or not images or len(images)!=len(set(images)) or any(i not in assets for i in images):
            raise SecurityError('Each image page requires exact registered assets')
    if set(assets) != {i for images in pages.values() for i in images}:
        raise SecurityError('Every image must be assigned to a reviewed page')
    return assets, pages.get(route, [])


def approved_image_counts(policy, route, image_paths):
    counts = policy.get('approved_page_image_counts', {})
    if not isinstance(counts, dict):
        raise SecurityError('Repeated images require an exact homepage approval')
    for key, values in counts.items():
        if key != 'index.html' or not isinstance(values, dict) or set(values) != set(policy.get('approved_page_images', {}).get(key, [])) or any(type(n) is not int or n != 2 for n in values.values()):
            raise SecurityError('Only reviewed foreground/background pairs may repeat')
    return counts.get(route, {name: 1 for name in image_paths})


def validate_image(data, name, meta):
    if len(data)>2*1024*1024 or hashlib.sha256(data).hexdigest()!=meta['sha256']:
        raise SecurityError('Image exceeds size limit or differs from reviewed bytes')
    dimensions=None
    if name.endswith('.png'):
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            raise SecurityError('Invalid PNG signature')
        offset=8
        while offset<len(data):
            if offset+12>len(data):raise SecurityError('Incomplete PNG')
            length=int.from_bytes(data[offset:offset+4],'big');kind=data[offset+4:offset+8]
            end=offset+12+length; payload=data[offset+8:offset+8+length]
            if end>len(data) or kind not in {b'IHDR',b'IDAT',b'IEND',b'sRGB',b'gAMA',b'cHRM',b'pHYs',b'PLTE',b'tRNS'}:
                raise SecurityError('PNG metadata or malformed chunk is prohibited')
            if zlib.crc32(kind+payload)&0xffffffff != int.from_bytes(data[end-4:end],'big'):
                raise SecurityError('Invalid PNG checksum')
            if kind==b'IHDR':dimensions=struct.unpack('>II',payload[:8])
            offset=end
            if kind==b'IEND':break
        if offset!=len(data) or kind!=b'IEND':raise SecurityError('PNG trailing or missing data')
    else:
        if not data.startswith(b'\xff\xd8') or not data.endswith(b'\xff\xd9'):raise SecurityError('Invalid JPEG signature')
        offset=2
        while offset<len(data)-2:
            if data[offset]!=255:raise SecurityError('Malformed JPEG segment')
            marker=data[offset+1];offset+=2
            if marker==0xda:break
            length=int.from_bytes(data[offset:offset+2],'big')
            if length<2 or offset+length>len(data):raise SecurityError('Malformed JPEG length')
            if marker==0xfe or 0xe1<=marker<=0xed or marker==0xef:raise SecurityError('JPEG private metadata prohibited')
            if marker in {0xc0,0xc1,0xc2}:
                height,width=struct.unpack('>HH',data[offset+3:offset+7]);dimensions=(width,height)
            offset+=length
    if dimensions!=(meta['width'],meta['height']):raise SecurityError('Image dimensions do not match review')


def image_target(src, route):
    parsed=urlsplit(src)
    if not route or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or src.startswith('/') or re.search(r'[\\%\s]',src):
        raise SecurityError('Image source must be an exact local relative path')
    return posixpath.normpath(posixpath.join(posixpath.dirname(route),src))


def page_csp(policy, route=None):
    urls = approved_embeds(policy, route)
    csp = CSP.replace("frame-src 'none'", "frame-src " + " ".join(urls)) if urls else CSP
    hashes = approved_scripts(policy, route)
    if hashes:
        csp = csp.replace("script-src 'none'", "script-src " + " ".join("'" + h + "'" for h in hashes) + "; script-src-attr 'none'")
    if approved_images(policy,route)[1]:
        csp = csp.replace("img-src 'none'", "img-src 'self'")
    fonts = approved_fonts(policy, route)
    if fonts:
        csp = csp.replace("font-src 'none'", 'font-src '+' '.join(WEBFONTS[name][1] for name in fonts))
    return csp


def validate_html(text, policy, path=None, site=None, route=None):
    check_text(text)
    if path is not None and site is not None:
        route = Path(path).resolve().relative_to(Path(site).resolve()).as_posix()
    embed_urls = approved_embeds(policy, route)
    script_hashes = approved_scripts(policy, route)
    image_assets, image_paths = approved_images(policy,route)
    image_counts = approved_image_counts(policy, route, image_paths)
    font_names = approved_fonts(policy, route)
    expected_csp = page_csp(policy, route)
    contact_links = policy.get("approved_contact_links", {})
    if not isinstance(contact_links, dict):
        raise SecurityError("Contact links require an exact page route")
    for contact_route, links in contact_links.items():
        if contact_route != "index.html" or not isinstance(links, list) or not links:
            raise SecurityError("Contact navigation is only approved for the homepage")
        for link in links:
            if not isinstance(link, str) or not re.fullmatch(r"(?:mailto:[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|tel:\+821[016789]\d{7,8})", link) or link.split(":", 1)[1] not in policy.get("approved_contacts", []):
                raise SecurityError("Contact links must match approved plain email or phone values")
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
            self.frames = set()
            self.images = set()
            self.image_counts = {}
            self.links = set()
            self.iframe_open = False
            self.script_open = False
            self.script_text = ""
            self.scripts = []
            self.fonts = []

        def handle_starttag(self, tag, attrs):
            if self.iframe_open:
                raise SecurityError("Embedded frames must be empty and explicitly closed")
            names = [name for name, _ in attrs]
            if len(names) != len(set(names)):
                raise SecurityError("Duplicate HTML attributes")
            values = dict(attrs)
            if tag in {"object", "embed", "base", "link", "form", "foreignobject"}:
                raise SecurityError("Scripts, frames, forms and external resources are prohibited")
            if tag == "script":
                if not self.csp or not script_hashes or attrs or self.script_open:
                    raise SecurityError("Only reviewed inline classic scripts after CSP are allowed")
                self.script_open = True
                self.script_text = ""
            if tag == 'img':
                if not self.csp or set(values)!={'src','alt','width','height','loading','decoding','class'}:
                    raise SecurityError('Images require reviewed attributes after CSP')
                target=image_target(values.get('src',''),route)
                self.image_counts[target] = self.image_counts.get(target, 0) + 1
                if target not in image_paths or self.image_counts[target] > image_counts[target]:
                    raise SecurityError('Unapproved or duplicate image')
                meta=image_assets[target]
                if not values['alt'].strip() or len(values['alt'])>240 or values['width']!=str(meta['width']) or values['height']!=str(meta['height']) or values['loading'] not in {'eager','lazy'} or values['decoding']!='async' or values['class']!='project-image':
                    raise SecurityError('Image description, layout or loading attributes invalid')
                self.images.add(target)
            if tag == "iframe":
                if not self.csp:
                    raise SecurityError("CSP must precede embedded resources")
                allowed_names = set(IFRAME_ATTRIBUTES) | {"src", "title", "allowfullscreen"}
                if set(values) != allowed_names:
                    raise SecurityError("YouTube iframe requires only the reviewed attributes")
                if any(values.get(key) != value for key, value in IFRAME_ATTRIBUTES.items()):
                    raise SecurityError("YouTube iframe permissions must match the reviewed limits")
                title = values.get("title") or ""
                if not title.strip() or len(title) > 120 or values.get("allowfullscreen") not in {None, ""}:
                    raise SecurityError("YouTube iframe requires a short title and boolean fullscreen")
                src = values.get("src")
                if src not in embed_urls or src in self.frames:
                    raise SecurityError("Unapproved or duplicate YouTube iframe for this component")
                self.frames.add(src)
                self.iframe_open = True
            for name, value in attrs:
                if tag in {"iframe", "img"} and name == "src":
                    continue
                if name.startswith("on") or name in {"srcdoc", "src", "srcset", "poster", "data", "xlink:href"}:
                    raise SecurityError("Executable attributes and remote resources are prohibited")
                if name == "style":
                    css_check(value or "")
            if tag == "meta":
                equiv = (values.get("http-equiv") or "").lower()
                if equiv and equiv != "content-security-policy":
                    raise SecurityError("Meta refresh and other HTTP-equivalent directives are prohibited")
                if equiv == "content-security-policy":
                    if self.csp or values.get("content") != expected_csp:
                        raise SecurityError("Missing or weakened static-page CSP")
                    self.csp = True
                if values.get("name") == "referrer":
                    if self.referrer or values.get("content") != "no-referrer":
                        raise SecurityError("Page navigation must retain a single no-referrer policy")
                    self.referrer = True
                if values.get("charset", "").lower() == "utf-8":
                    self.charset = True
                if values.get("name") == "viewport":
                    self.viewport = True
            if tag == "a":
                href = values.get("href") or ""
                self.links.add(href)
                parsed = urlsplit(href)
                if not href or "\\" in href or re.search(r"[\x00-\x20]", href):
                    raise SecurityError("Unsafe or empty hyperlink")
                if parsed.scheme in {"mailto", "tel"}:
                    if href not in contact_links.get(route, []) or values.get("target"):
                        raise SecurityError("Unapproved contact navigation")
                elif parsed.scheme or parsed.netloc:
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
            if tag in {"iframe", "script"}:
                raise SecurityError("Embedded frames require an explicit closing tag")
            self.handle_starttag(tag, attrs)

        def handle_endtag(self, tag):
            if tag == "script":
                if not self.script_open:
                    raise SecurityError("Unexpected script closing tag")
                digest = script_hash(self.script_text)
                if digest not in script_hashes or digest in self.scripts:
                    raise SecurityError("Unreviewed, modified or duplicate inline script")
                self.scripts.append(digest)
                self.script_open = False
            if tag == "iframe":
                if not self.iframe_open:
                    raise SecurityError("Unexpected iframe closing tag")
                self.iframe_open = False
            elif self.iframe_open:
                raise SecurityError("Embedded frames must be explicitly closed")
            if tag == "style":
                self.styles = False

        def handle_comment(self, text):
            if self.iframe_open:
                raise SecurityError("Embedded frames must not contain comments")

        def handle_data(self, text):
            if self.script_open:
                self.script_text += text
            if self.iframe_open and text.strip():
                raise SecurityError("Embedded frames must not contain fallback markup")
            if self.styles:
                self.fonts.extend(css_check(text, font_names))

    page = StaticPage()
    page.feed(text)
    page.close()
    if page.script_open or set(page.scripts) != set(script_hashes):
        raise SecurityError("Page must include exactly its reviewed complete scripts")
    if page.iframe_open:
        raise SecurityError("Embedded frame is not closed")
    if page.frames != set(embed_urls):
        raise SecurityError("An embed exception must contain exactly its approved video frames")
    if page.images != set(image_paths):
        raise SecurityError('Image page must include exactly its reviewed assets')
    if page.image_counts != image_counts:
        raise SecurityError('Image page must include exactly its reviewed image counts')
    if sorted(page.fonts) != sorted(font_names):
        raise SecurityError('Page must include exactly its reviewed font declarations')
    if any(youtube_watch_url(url) not in page.links for url in page.frames):
        raise SecurityError("Every embedded video requires an ordinary watch-on-YouTube fallback")
    if not all((page.csp, page.referrer, page.charset, page.viewport)):
        raise SecurityError("Page requires CSP, no-referrer, UTF-8 and viewport metadata")


def validate_repository(root):
    root = Path(root).resolve()
    policy = json.loads((root / "policy.json").read_text(encoding="utf-8"))
    images,_ = approved_images(policy)
    files = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if any(part in {".git", "__pycache__"} for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            raise SecurityError("Symbolic links must never enter the public export")
        if not path.is_file():
            continue
        if relative.removeprefix('docs/') in images and relative.startswith('docs/'):
            validate_image(path.read_bytes(),relative.removeprefix('docs/'),images[relative.removeprefix('docs/')])
            files.append(relative)
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
    if {'docs/'+n for n in images} - set(files):raise SecurityError('Approved image asset is missing')
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


def validate_outgoing_history(root):
    """Check unpublished commits too, including data deleted in the current tree."""
    root = Path(root).resolve()
    if not (root / ".git").exists():
        return {"outgoing_commits_checked": 0}
    def git(*args):
        return subprocess.run(["git", "-c", "safe.directory=" + root.as_posix(), *args],
                              cwd=root, check=True, capture_output=True).stdout
    commits = git("rev-list", "HEAD", "--not", "--remotes").decode().splitlines()
    for commit in commits:
        policy = json.loads(git("show", commit + ":policy.json").decode("utf-8"))
        images,_ = approved_images(policy)
        blobs = {}
        for line in git("ls-tree", "-r", "--format=%(objectmode) %(objectname) %(path)", commit).decode().splitlines():
            mode, sha, name = line.split(" ", 2)
            if mode not in {"100644", "100755"} or (name not in PUBLIC_FILES and not COMPONENT_PATH.fullmatch(name) and name not in {'docs/'+i for i in images}):
                raise SecurityError("Unexpected file or link in outgoing Git history")
            data = git("cat-file", "blob", sha)
            if name in {'docs/'+i for i in images}:
                validate_image(data,name.removeprefix('docs/'),images[name.removeprefix('docs/')]);blobs[name]=data;continue
            if len(data) > 250 * 1024:
                raise SecurityError("Oversized file in outgoing Git history")
            text = data.decode("utf-8")
            check_text(text)
            if name.endswith(".html"):
                validate_html(text, policy, route=name.removeprefix("docs/"))
            blobs[name] = data
        catalog = json.loads(blobs["docs/catalog.json"])
        if {'docs/'+n for n in images} - set(blobs):raise SecurityError('Approved image missing from history')
        routes = {p["path"] for p in catalog["pages"]}
        if routes != {name.removeprefix("docs/") for name in blobs if name.endswith(".html")}:
            raise SecurityError("Unregistered HTML in outgoing Git history")
        for entry in catalog["pages"]:
            if hashlib.sha256(blobs["docs/" + entry["path"]]).hexdigest() != entry["sha256"]:
                raise SecurityError("HTML hash mismatch in outgoing Git history")
    return {"outgoing_commits_checked": len(commits)}


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    cli.add_argument("--history", action="store_true")
    args = cli.parse_args()
    try:
        result = validate_repository(args.root)
        if args.history:
            result.update(validate_outgoing_history(args.root))
        print(json.dumps(result, ensure_ascii=False))
    except (SecurityError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("Public export stopped: " + str(exc))
