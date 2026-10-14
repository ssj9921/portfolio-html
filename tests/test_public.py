import hashlib
import json
import re
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_public import CSP, IFRAME_ATTRIBUTES, page_csp, script_hash, SecurityError, validate_html, validate_repository, validate_outgoing_history, validate_image, font_css

POLICY = {"approved_external_links": ["https://example.com/public"], "approved_contacts": []}


def page(body="", style=""):
    return ('<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="referrer" content="no-referrer">'
            '<meta http-equiv="Content-Security-Policy" content="' + CSP + '">'
            '<style>' + style + '</style></head><body>' + body + '</body></html>')


class PublicPolicyTests(unittest.TestCase):
    def test_inline_ugc_demo_is_scoped_and_keeps_parent_navigation(self):
        root = Path(__file__).resolve().parents[1] / 'docs'
        text = (root/'components/zeta-ugc-event/v1.1.0/index.html').read_text(encoding='utf-8')
        code = re.search(r'<script>([\s\S]*?)</script>', text)[1]
        self.assertIn('<details class="ugc-experience" id="ugc-experience">', text)
        self.assertIn('id="ugc-demo"', text)
        for token in ['location.', 'history.', 'window.addEventListener', 'document.querySelector']:
            self.assertNotIn(token, code)
        self.assertIn("root.querySelector", code)
        self.assertNotIn('<iframe', text)
        self.assertIn("frame-src 'none'", text)
        self.assertIn('전체 화면으로 열기', text)
        self.assertIn('zeta-ugc-wireframes/v1.0.1/index.html', text)
        self.assertIn('name="ugc-scene"', text)
        ids = re.findall(r'\bid="([^"]+)"', text)
        self.assertEqual(len(ids), len(set(ids)))

    def test_ugc_proposal_preserves_source_boundaries_and_offline_demo(self):
        root = Path(__file__).resolve().parents[1] / 'docs'
        detail = (root/'components/zeta-ugc-event/v1.0.0/index.html').read_text(encoding='utf-8')
        demo = (root/'components/zeta-ugc-wireframes/v1.0.0/index.html').read_text(encoding='utf-8')
        for phrase in ['미집행', '가상 데이터', '보조 도식', '추가 검토안', '마이페이지', '원작자', '채팅 제출자']:
            self.assertIn(phrase, detail)
        self.assertEqual(detail.count('<section aria-labelledby='), 5)
        self.assertNotIn('<img', demo)
        self.assertNotIn('Task/', detail + demo)
        self.assertNotIn('04-profile_', demo)
        self.assertIn('data-screen="mypage"', demo)
        self.assertNotIn('class="app-nav" aria-label="예시 앱 주요 메뉴"><button type="button" data-go="profile"', demo)
        self.assertIn('공개 포크 · 제안', demo)
        self.assertIn("connect-src 'none'", demo)
        self.assertIn('noscript', demo)

    def test_homepage_script_needs_explicit_flag_and_exact_hash(self):
        code = "document.body.classList.add('ready');"
        policy = dict(POLICY, javascript_allowed=True, homepage_script_allowed=True,
                      approved_inline_scripts={'index.html':[script_hash(code)]})
        html = page('<script>' + code + '</script>').replace(CSP, page_csp(policy, 'index.html'))
        validate_html(html, policy, route='index.html')
        for changed in [html.replace("'ready'", "'other'"), html.replace('<script>'+code+'</script>', '')]:
            with self.assertRaises(SecurityError): validate_html(changed, policy, route='index.html')
        with self.assertRaises(SecurityError): validate_html(html, dict(policy, homepage_script_allowed=False), route='index.html')
        with self.assertRaises(SecurityError): validate_html(html, policy, route='components/other/v1.0.0/index.html')

    def test_homepage_image_pairs_do_not_allow_extra_or_missing_copies(self):
        root = Path(__file__).resolve().parents[1]
        policy = json.loads((root/'policy.json').read_text(encoding='utf-8'))
        html = (root/'docs/index.html').read_text(encoding='utf-8')
        img = re.search(r'<img[^>]+>', html)[0]
        for changed in [html.replace(img, '', 1), html.replace('</body>', img+'</body>')]:
            with self.assertRaises(SecurityError): validate_html(changed, policy, route='index.html')
        with self.assertRaises(SecurityError): validate_html(html, dict(policy, approved_page_image_counts={}), route='index.html')

    def test_contact_links_require_exact_homepage_approval(self):
        email = 'contact' + '@example.com'
        phone = '+821012345678'
        policy = dict(POLICY, approved_contacts=[email, phone, '010.1234.5678'],
                      approved_contact_links={'index.html': ['mailto:' + email, 'tel:' + phone]})
        body = '<a href="mailto:' + email + '">Email</a><a href="tel:' + phone + '">010.1234.5678</a>'
        validate_html(page(body), policy, route='index.html')
        for route in [None, 'components/example/v1.0.0/index.html']:
            with self.subTest(route=route), self.assertRaises(SecurityError):
                validate_html(page(body), policy, route=route)
        for link in ['mailto:' + email + '?subject=Hello', 'mailto:' + email + '#other',
                     'tel:' + phone + ';ext=1', 'tel:+821012345679']:
            with self.subTest(link=link), self.assertRaises(SecurityError):
                validate_html(page('<a href="' + link + '">Contact</a>'), policy, route='index.html')

    def test_phone_disclosure_checks_include_dotted_and_international_values(self):
        for value in ['010.1234.5678', '010-1234-5678', '+821012345678']:
            with self.subTest(value=value), self.assertRaises(SecurityError):
                validate_html(page('<p>' + value + '</p>'), POLICY)

    def test_contact_policy_cannot_grant_other_schemes_or_query_parameters(self):
        for link in ['https://example.com/public', 'mailto:a@example.com?cc=b@example.com', 'tel:+821012345678;ext=1']:
            policy = dict(POLICY, approved_contacts=[link.split(':', 1)[1]],
                          approved_contact_links={'index.html': [link]})
            with self.subTest(link=link), self.assertRaises(SecurityError):
                validate_html(page(), policy, route='index.html')

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

    def test_secret_removed_from_working_tree_still_blocks_outgoing_history(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "docs").mkdir()
            (root / "policy.json").write_text(json.dumps(POLICY), encoding="utf-8")
            def git(*args):
                subprocess.run(["git", "-c", "safe.directory=" + root.as_posix(), *args],
                               cwd=root, check=True, capture_output=True)
            def commit_html(body):
                data = page(body).encode()
                (root / "docs/index.html").write_bytes(data)
                (root / "docs/catalog.json").write_text(json.dumps({"pages": [{"path": "index.html", "sha256": hashlib.sha256(data).hexdigest()}]}), encoding="utf-8")
                git("add", ".")
                git("commit", "-m", "Test history")
            git("init", "--initial-branch=main")
            git("config", "user.name", "Security test")
            git("config", "user.email", "public-test" + "@example.invalid")
            commit_html("ghp" + "_" + "x" * 30)
            commit_html("Safe current page")
            self.assertTrue(validate_repository(root)["valid"])
            with self.assertRaises(SecurityError):
                validate_outgoing_history(root)


class YouTubeEmbedPolicyTests(unittest.TestCase):
    route = "components/varco-project/v1.0.0/index.html"
    src = "https://www.youtube-nocookie.com/embed/QewprwQ5BGc"
    watch = "https://www.youtube.com/watch?v=QewprwQ5BGc"

    def setUp(self):
        self.policy = {**POLICY, "approved_external_links": [*POLICY["approved_external_links"], self.watch],
                       "approved_youtube_embeds": {self.route: [self.src]}}
        attrs = " ".join(key + '="' + value + '"' for key, value in IFRAME_ATTRIBUTES.items())
        self.iframe = '<iframe src="' + self.src + '" title="CityOfRubble 영상" ' + attrs + ' allowfullscreen></iframe>'
        self.fallback = '<a href="' + self.watch + '" target="_blank" rel="noopener noreferrer">YouTube에서 보기</a>'
        self.html = page(self.iframe + self.fallback).replace(CSP, page_csp(self.policy, self.route))

    def validate(self, html, **kwargs):
        validate_html(html, self.policy, route=self.route, **kwargs)

    def test_exact_approved_video_passes_only_on_its_component(self):
        self.validate(self.html)
        with tempfile.TemporaryDirectory() as folder:
            site = Path(folder) / "docs"
            validate_html(self.html, self.policy, site / self.route, site)
        for route in (None, "index.html", "components/varco-project/v1.0.1/index.html"):
            with self.subTest(route=route), self.assertRaises(SecurityError):
                validate_html(self.html, self.policy, route=route)
        validate_html(page(), self.policy)
        self.assertEqual(page_csp(self.policy, "index.html"), CSP)

    def test_external_origins_urls_and_parameters_fail(self):
        for src in ("https://example.com/frame", "https://www.youtube.com/embed/QewprwQ5BGc",
                    "https://www.youtube-nocookie.com.evil.test/embed/QewprwQ5BGc",
                    "https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ",
                    self.src + "?autoplay=1", self.src + "?enablejsapi=1", self.src + "#fragment",
                    "http://www.youtube-nocookie.com/embed/QewprwQ5BGc", "//www.youtube-nocookie.com/embed/QewprwQ5BGc"):
            with self.subTest(src=src), self.assertRaises(SecurityError):
                self.validate(self.html.replace('src="' + self.src + '"', 'src="' + src + '"'))

    def test_scoped_csp_cannot_allow_other_resources_or_broader_frames(self):
        for old, new in ((self.src, "https://www.youtube-nocookie.com"),
                         ("script-src 'none'", "script-src 'unsafe-inline'"),
                         ("object-src 'none'", "object-src 'self'"),
                         ("img-src 'none'", "img-src https:"),
                         ("frame-src " + self.src, "frame-src https://example.com " + self.src)):
            with self.subTest(new=new), self.assertRaises(SecurityError):
                self.validate(self.html.replace(old, new, 1))
        with self.assertRaises(SecurityError):
            self.validate(self.html.replace(page_csp(self.policy, self.route), CSP))

    def test_iframe_permissions_and_attributes_are_fixed(self):
        for attr, value in IFRAME_ATTRIBUTES.items():
            for replacement in ("", attr + '="unexpected"'):
                with self.subTest(attr=attr, replacement=replacement), self.assertRaises(SecurityError):
                    self.validate(self.html.replace(attr + '="' + value + '"', replacement))
        for extra in ('srcdoc="hello"', 'onload="alert(1)"', 'allow="autoplay"',
                      'credentialless', 'style="display:none"', 'name="target"'):
            with self.subTest(extra=extra), self.assertRaises(SecurityError):
                self.validate(self.html.replace('<iframe ', '<iframe ' + extra + ' '))
        for old, new in (('title="CityOfRubble 영상"', 'title=""'),
                         (' allowfullscreen', ''), (' allowfullscreen', ' allowfullscreen="yes"')):
            with self.subTest(new=new), self.assertRaises(SecurityError):
                self.validate(self.html.replace(old, new))

    def test_missing_duplicate_or_malformed_frames_and_fallback_fail(self):
        cases = [self.html.replace(self.fallback, ''), self.html.replace(self.iframe, ''),
                 self.html.replace(self.iframe, self.iframe * 2),
                 self.html.replace('</iframe>', ''), self.html.replace('></iframe>', '/>'),
                 self.html.replace('</iframe>', self.fallback + '</iframe>'),
                 self.html.replace('</iframe>', '<!-- frame content --></iframe>'),
                 self.html.replace('<style>', self.iframe + '<style>')]
        for html in cases:
            with self.subTest(html=html), self.assertRaises(SecurityError):
                self.validate(html)
        with self.assertRaises(SecurityError):
            self.validate(self.html.replace('<meta charset="utf-8">', self.iframe + '<meta charset="utf-8">'))

    def test_other_executable_features_stay_blocked_on_embed_page(self):
        for body in ('<script></script>', '<object></object>', '<embed>', '<form></form>',
                     '<img src="https://example.com/a.png">', '<div onclick="alert(1)"></div>',
                     '<iframe src="https://example.com"></iframe>'):
            with self.subTest(body=body), self.assertRaises(SecurityError):
                self.validate(self.html.replace('</body>', body + '</body>'))

    def test_approval_configuration_is_fail_closed(self):
        for approved in ([], {"index.html": [self.src]}, {self.route: []}, {self.route: self.src},
                         {self.route: [self.src, self.src]}, {self.route: [self.src + '?autoplay=1']},
                         {self.route: ['https://example.com/embed/QewprwQ5BGc']}, {self.route: [None]}):
            with self.subTest(approved=approved), self.assertRaises(SecurityError):
                validate_html(page(), {**self.policy, "approved_youtube_embeds": approved})
        with self.assertRaises(SecurityError):
            validate_html(page(), {**self.policy, "approved_external_links": []})

    def test_navigation_referrer_policy_remains_private(self):
        for html in (self.html.replace('content="no-referrer"', 'content="origin"'),
                     self.html.replace('</head>', '<meta name="referrer" content="origin"></head>')):
            with self.subTest(html=html), self.assertRaises(SecurityError):
                self.validate(html)

    def test_repository_and_outgoing_history_apply_the_same_route_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "docs" / self.route
            target.parent.mkdir(parents=True)
            target.write_text(self.html, encoding="utf-8")
            (root / "policy.json").write_text(json.dumps(self.policy), encoding="utf-8")
            catalog = {"pages": [{"path": self.route, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}]}
            (root / "docs/catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
            self.assertTrue(validate_repository(root)["valid"])
            def git(*args):
                subprocess.run(["git", "-c", "safe.directory=" + root.as_posix(), *args],
                               cwd=root, check=True, capture_output=True)
            git("init", "--initial-branch=main")
            git("config", "user.name", "Security test")
            git("config", "user.email", "public-test" + "@example.invalid")
            git("add", ".")
            git("commit", "-m", "Test scoped embed")
            self.assertEqual(validate_outgoing_history(root)["outgoing_commits_checked"], 1)
            moved = root / "docs/index.html"
            target.rename(moved)
            catalog["pages"][0]["path"] = "index.html"
            (root / "docs/catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
            git("add", ".")
            git("commit", "-m", "Test unapproved route")
            with self.assertRaises(SecurityError):
                validate_repository(root)
            with self.assertRaises(SecurityError):
                validate_outgoing_history(root)


class PortfolioMigrationTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[1]
    project = "components/heros-chef-project/v1.0.2/index.html"
    profile = "components/profile/v1.0.2/index.html"
    projects = "components/projects/v1.0.0/index.html"

    def test_complete_public_export_passes(self):
        result = validate_repository(self.root)
        self.assertTrue(result["valid"])
        self.assertEqual(result["html_pages"], 91)

    def test_four_primary_pages_use_internal_navigation(self):
        home = (self.root / "docs/index.html").read_text(encoding="utf-8")
        for route in (self.project, self.profile, self.projects):
            current = route.replace('v1.0.2/', 'v1.0.3/').replace('projects/v1.0.0/', 'projects/v2.7.0/').replace('heros-chef-project/v1.0.3/','heros-chef-project/v1.3.4/').replace('profile/v1.0.3/','profile/v1.2.8/')
            self.assertIn('href="' + current + '"', home)
        for route in ("index.html", self.project, self.profile, self.projects):
            text = (self.root / "docs" / route).read_text(encoding="utf-8")
            self.assertNotIn("notion.site", text)
        project = (self.root / "docs" / self.project).read_text(encoding="utf-8")
        self.assertIn('href="https://drive.google.com/drive/folders/', project)

    def test_home_header_and_intro_spacing_match_detail_pages(self):
        home = (self.root / "docs/index.html").read_text(encoding="utf-8")
        header_rules = re.findall(r"(?<![\w.-])header\{([^}]+)\}", home)
        wrap_rules = re.findall(r"\.wrap\{([^}]+)\}", home)
        self.assertEqual(len(header_rules), 2)
        for route in (self.project, self.profile, self.projects):
            detail = (self.root / "docs" / route).read_text(encoding="utf-8")
            self.assertEqual(header_rules, re.findall(r"(?<![\w.-])header\{([^}]+)\}", detail))
            self.assertEqual(wrap_rules, re.findall(r"\.wrap\{([^}]+)\}", detail))
            for text in (home, detail):
                hero_rules = re.findall(r"\.hero\{([^}]+)\}", text)
                self.assertIn("padding:62px 0 42px", hero_rules[0])
                self.assertRegex(text, r"@media\(max-width:800px\)\{[^@]*\.hero\{padding:44px 0 30px\}")
                self.assertRegex(text, r"@media\(max-width:580px\)\{[^@]*\.hero\{padding-top:32px\}")
                self.assertIn("min-height:44px", re.search(r"\.brand\{([^}]+)\}", text)[1])

    def test_current_pages_link_to_dedicated_projects_listing(self):
        home = (self.root / "docs/index.html").read_text(encoding="utf-8")
        self.assertIn('href="' + self.projects.replace('v1.0.0/', 'v2.7.0/') + '">Projects</a>', home)
        for route in (self.profile, self.project):
            text = (self.root / "docs" / route).read_text(encoding="utf-8")
            self.assertRegex(text, r'href="../../projects/v1.0.0/index.html"[^>]*>Projects</a>')
            self.assertIn('href="../../projects/v1.0.0/index.html">← 프로젝트 목록</a>', text)
        projects = (self.root / "docs" / self.projects).read_text(encoding="utf-8")
        self.assertIn('href="../../heros-chef-project/v1.0.2/index.html"', projects)
        for route in ("index.html", self.projects, self.profile, self.project):
            text = (self.root / "docs" / route).read_text(encoding="utf-8")
            self.assertNotIn('/profile/v1.0.0/', text)
            self.assertNotIn('/profile/v1.0.1/', text)
            self.assertNotIn('index.html#selected-title', text)

    def test_projects_cards_reserve_intro_and_omit_unpublished_work(self):
        text = (self.root / "docs" / self.projects).read_text(encoding="utf-8")
        self.assertEqual(text.count('class="project-card"'), 1)
        self.assertEqual(text.count('소개 문구 작성 예정'), 2)
        for phrase in ('용사의 쉐프', '공모전 제출 완료', '용량 제한 충족'):
            self.assertIn(phrase, text)
        self.assertIn('grid-template-columns:repeat(2,minmax(0,1fr))', text)
        self.assertIn('.project-grid{grid-template-columns:1fr;', text)
        self.assertNotIn('CityOfRubble', text)
        self.assertNotIn('상세 페이지 준비 중', text)
        self.assertNotIn('aria-disabled', text)
        self.assertNotIn('href="#"', text)

    def test_new_detail_versions_only_update_navigation(self):
        for component in ("profile", "heros-chef-project"):
            folder = self.root / "docs/components" / component
            old = (folder / "v1.0.1/index.html").read_text(encoding="utf-8")
            expected = old.replace("../../profile/v1.0.1/", "../../profile/v1.0.2/")
            if component == "profile":
                expected = expected.replace("../../../index.html#selected-title", "../../projects/v1.0.0/index.html")
                expected = expected.replace(">Project</a>", ">Projects</a>").replace(">Project 보기 →</a>", ">Projects 보기 →</a>")
            else:
                expected = expected.replace('../../heros-chef-project/v1.0.1/index.html" aria-current="page">Project', '../../projects/v1.0.0/index.html" aria-current="location">Projects')
                expected = expected.replace('href="../../../index.html">← 프로젝트 목록', 'href="../../projects/v1.0.0/index.html">← 프로젝트 목록')
            self.assertEqual((folder / "v1.0.2/index.html").read_text(encoding="utf-8"), expected)

    def test_patch_pages_only_change_navigation(self):
        for component in ("profile", "heros-chef-project"):
            folder = self.root / "docs/components" / component
            old = (folder / "v1.0.0/index.html").read_text(encoding="utf-8")
            expected = old.replace("../../profile/v1.0.0/", "../../profile/v1.0.1/")
            if component == "profile":
                expected = expected.replace("../../heros-chef-project/v1.0.0/index.html", "../../../index.html#selected-title")
                expected = expected.replace('href="../../../index.html">← 프로젝트 목록', 'href="../../../index.html#selected-title">← 프로젝트 목록')
            else:
                expected = expected.replace("../../heros-chef-project/v1.0.0/", "../../heros-chef-project/v1.0.1/")
            self.assertEqual((folder / "v1.0.1/index.html").read_text(encoding="utf-8"), expected)

    def test_project_follows_five_sections_and_attributes_ai(self):
        project = (self.root / "docs" / self.project).read_text(encoding="utf-8")
        headings = ["01 · 아이디어", "02 · 무엇을 만든 건지", "03 · 환경", "04 · 작업물", "05 · 코멘트"]
        positions = [project.index('<h2 id="' + anchor + '">' + heading) for anchor, heading in zip(
            ("idea", "about", "environment", "work", "comment"), headings)]
        self.assertEqual(positions, sorted(positions))
        for phrase in ("아이디어 제공 외 전체", "1,474,560바이트 이하", "재미나 사용성을 측정한 결과는 아닙니다",
                       "파일을 다시 실행하거나 최종 바이트 수를 재측정하지 않았으며", "작성 예정"):
            self.assertIn(phrase, project)
        self.assertNotIn("우수상", project)
        self.assertNotIn("NC AI VARCO", project)

    def test_profile_keeps_approved_facts_and_expected_status(self):
        profile = (self.root / "docs" / self.profile).read_text(encoding="utf-8")
        for phrase in ("SEUNGJIN SONG", "디벨로켓에듀", "2023.06 ~ 2025.03", "게임 기획 교강사",
                       "모비릭스", "2021.11 ~ 2023.06", "아이오넷 / 브릿지 게임즈", "2020.06 ~ 2021.08",
                       "공학사 학위취득 예정 · 2027.02", "정밀화학과 · 중퇴", "컴퓨터활용능력 2급",
                       "2026.03.31", "데이터분석 준전문가", "2026.06.06", "NC AI VARCO 3D 인디게임 공모전",
                       "우수상", "2025.09.22"):
            self.assertIn(phrase, profile)
        self.assertNotIn("mailto:", profile)
        self.assertNotIn("tel:", profile)

    def test_superseded_detail_pages_are_not_in_export(self):
        catalog = json.loads((self.root / "docs/catalog.json").read_text(encoding="utf-8"))
        routes = {p["path"] for p in catalog["pages"]}
        for kind in ("product", "retrospective"):
            old = "components/heros-chef-" + kind + "/v1.0.0/index.html"
            self.assertNotIn(old, routes)
            self.assertFalse((self.root / "docs" / old).exists())

    def test_internal_routes_and_fragment_targets_exist(self):
        class Links(HTMLParser):
            def __init__(self, text):
                super().__init__()
                self.ids = set()
                self.hrefs = []
                self.feed(text)

            def handle_starttag(self, tag, attrs):
                values = dict(attrs)
                if "id" in values:
                    if values["id"] in self.ids:
                        raise AssertionError("Duplicate HTML id")
                    self.ids.add(values["id"])
                if tag == "a":
                    self.hrefs.append(values.get("href", ""))

        site = self.root / "docs"
        pages = {path.resolve(): Links(path.read_text(encoding="utf-8")) for path in site.rglob("*.html")}
        for path, page in pages.items():
            for href in page.hrefs:
                parsed = urlsplit(href)
                if parsed.scheme or parsed.netloc:
                    continue
                target = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
                if target.suffix in {'.png','.jpg'}:
                    policy=json.loads((self.root/'policy.json').read_text(encoding='utf-8'))
                    self.assertIn(target.relative_to(site).as_posix(),policy['approved_image_assets'])
                    self.assertTrue(target.is_file())
                    self.assertFalse(parsed.fragment)
                    continue
                self.assertIn(target, pages, f"Missing route: {href}")
                if parsed.fragment:
                    self.assertIn(unquote(parsed.fragment), pages[target].ids, f"Missing anchor: {href}")

    def test_existing_component_bytes_remain_unchanged(self):
        expected = {
            "profile/v1.0.1": "2ace29474e9cd090659864bf6886121a3c70d205b9b3e0349b6b22c55ce5b9e6",
            "heros-chef-project/v1.0.1": "474a2302f7445c26983813301308159be29fb51951d05ded97988563016be49a",
            "profile/v1.0.0": "255c731b619d0d40de9e5f897b6f589eb22c4608d9060eb85892ece6d0a21520",
            "heros-chef-project/v1.0.0": "7c6c01c56ec2940738ea7f2ec29db18cd1f1ecc24142f5f014cc84daccbdb5b5",
            "editorial-hero/v1.0.0": "9a236c5839e1af4b2a9f1bdf98d946faaf2ef0ba82950e52b6a86e6f249d6de8",
            "selected-work-intro/v1.1.0": "9aebd02fc09bb215b88e2a539a85c51ec2a8d69dd7f1d63f1850dba1363e35cc",
            "product-retrospective-tabs/v1.1.0": "78cbbf8144c5d45c8588c5bd65f66385c0cf34bb1dd0981f1b7f5cd8ebb55606",
            "editorial-footer/v1.0.0": "9ee80e3a66bece73fa15b13a814b2a66cd885e30ec6b83bfd38894100e57e2f8",
            "project-card/v1.0.0": "6331cdbf6ca6d237709d0c02e5eabae5d95f0d43f0a5ec2a2a20038880c7203c",
            "timeline/v1.1.0": "22082939c5f726a2d77df7316d622c1f2dda2427381a4747a96411b7da080065",
        }
        for route, digest in expected.items():
            data = (self.root / "docs/components" / route / "index.html").read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)


class FirstPartyScriptTests(unittest.TestCase):
    route = 'components/demo/v1.0.0/index.html'
    code = "document.querySelector('button').addEventListener('click', () => {});"

    def setUp(self):
        self.hash = script_hash(self.code)
        self.policy = {**POLICY, 'javascript_allowed': True, 'approved_inline_scripts': {self.route: [self.hash]}}
        self.html = page('<button>Demo</button><script>' + self.code + '</script>').replace(CSP, page_csp(self.policy, self.route))

    def test_exact_hash_and_route_required(self):
        validate_html(self.html, self.policy, route=self.route)
        for route in (None, 'index.html', self.route.replace('1.0.0', '1.0.1')):
            with self.subTest(route=route), self.assertRaises(SecurityError):
                validate_html(self.html, self.policy, route=route)
        self.assertEqual(page_csp(self.policy, 'index.html'), CSP)

    def test_modification_removal_duplicate_and_incomplete_script_fail(self):
        for text in (self.html.replace(self.code, self.code + ' '),
                     self.html.replace('<script>' + self.code + '</script>', ''),
                     self.html.replace('</body>', '<script>' + self.code + '</script></body>'),
                     self.html.replace('</script>', ''), self.html.replace('<script>', '<script/>')):
            with self.subTest(text=text), self.assertRaises(SecurityError):
                validate_html(text, self.policy, route=self.route)

    def test_external_scripts_attributes_and_execution_features_fail(self):
        for attr in ('src="https://example.com/code.js"', 'src="code.js"', 'type="module"', 'nonce="x"', 'defer'):
            with self.subTest(attr=attr), self.assertRaises(SecurityError):
                validate_html(self.html.replace('<script>', '<script '+attr+'>'), self.policy, route=self.route)
        for extra in ('<div onclick="alert(1)"></div>', '<iframe></iframe>', '<form></form>', '<img src="x.png">'):
            with self.subTest(extra=extra), self.assertRaises(SecurityError):
                validate_html(self.html.replace('</body>', extra+'</body>'), self.policy, route=self.route)

    def test_policy_cannot_enable_broad_script_or_network_permissions(self):
        for text in (self.html.replace("'"+self.hash+"'", "'unsafe-inline'"),
                     self.html.replace("connect-src 'none'", "connect-src 'self'"),
                     self.html.replace("script-src-attr 'none'", "script-src-attr 'unsafe-inline'")):
            with self.subTest(text=text), self.assertRaises(SecurityError):
                validate_html(text, self.policy, route=self.route)
        for approved in ([], {'index.html':[self.hash]}, {self.route:[]}, {self.route:['bad']}, {self.route:[self.hash,self.hash]}):
            with self.subTest(approved=approved), self.assertRaises(SecurityError):
                validate_html(page(), {**self.policy,'approved_inline_scripts':approved})
        with self.assertRaises(SecurityError):
            validate_html(self.html,{**self.policy,'javascript_allowed':False},route=self.route)

    def test_history_also_requires_exact_script_approval(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); target = root/'docs'/self.route
            target.parent.mkdir(parents=True); target.write_text(self.html,encoding='utf-8')
            (root/'policy.json').write_text(json.dumps(self.policy),encoding='utf-8')
            (root/'docs/catalog.json').write_text(json.dumps({'pages':[{'path':self.route,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}]}),encoding='utf-8')
            def git(*args):
                subprocess.run(['git','-c','safe.directory='+root.as_posix(),*args],cwd=root,check=True,capture_output=True)
            git('init','--initial-branch=main'); git('config','user.name','Security test'); git('config','user.email','test'+'@example.invalid')
            git('add','.'); git('commit','-m','Reviewed script')
            self.assertEqual(validate_outgoing_history(root)['outgoing_commits_checked'],1)
            target.write_text(self.html.replace(self.code,self.code+' '),encoding='utf-8')
            git('add','.'); git('commit','-m','Changed script')
            with self.assertRaises(SecurityError): validate_outgoing_history(root)

class StockReleaseTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[1] / 'docs'

    def test_new_navigation_preserves_old_documents(self):
        projects = (self.root/'components/projects/v1.1.0/index.html').read_text(encoding='utf-8')
        self.assertEqual(projects.count('class="project-card"'),2)
        for route in ('stock-project','stock-demo'):
            self.assertIn('../../'+route+'/v1.0.0/index.html',projects)
        for name in ('heros-chef-project','profile'):
            old = (self.root/f'components/{name}/v1.0.2/index.html').read_text(encoding='utf-8')
            expected = old.replace('../../projects/v1.0.0/','../../projects/v1.1.0/').replace('../../profile/v1.0.2/','../../profile/v1.0.3/').replace('../../heros-chef-project/v1.0.2/','../../heros-chef-project/v1.0.3/')
            self.assertEqual((self.root/f'components/{name}/v1.0.3/index.html').read_text(encoding='utf-8'),expected)
        self.assertNotIn('../../varco-project/',projects)
        self.assertTrue((self.root/'components/visual-novel-template/v1.0.0/index.html').is_file())

    def test_stock_keeps_source_boundaries_and_five_sections(self):
        project = (self.root/'components/stock-project/v1.0.0/index.html').read_text(encoding='utf-8')
        positions = [project.index('<h2 id="'+anchor+'">') for anchor in ('idea','about','environment','work','comment')]
        self.assertEqual(positions,sorted(positions))
        for phrase in ('작성 예정','실제 매매 수익률','가상 예시','실제 사용자 조사나 성과 측정은 수행하지 않았습니다','AI 활용'):
            self.assertIn(phrase,project)
        for text in (project,(self.root/'components/stock-demo/v1.0.0/index.html').read_text(encoding='utf-8')):
            self.assertNotIn('Stock_Reference',text)
            self.assertNotIn('portfolio.md',text)
            self.assertNotIn('<iframe',text)


class StockIntegrationTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[1] / 'docs'

    def test_in_document_integration_preserves_explanation(self):
        old = (self.root/'components/stock-project/v1.0.0/index.html').read_text(encoding='utf-8')
        new = (self.root/'components/stock-project/v1.1.0/index.html').read_text(encoding='utf-8')
        for anchor in ('idea','about','environment','comment'):
            pattern = r'<section aria-labelledby="'+anchor+r'">.*?</section>'
            self.assertEqual(re.search(pattern,old,re.S)[0],re.search(pattern,new,re.S)[0])
        self.assertEqual(new.count('<main '),1)
        self.assertEqual(new.count('<h1>'),1)
        self.assertNotIn('<iframe',new)
        self.assertNotIn('window.StockModel',new)
        self.assertNotIn('document.addEventListener',new)
        self.assertIn('id="stock-widget"',new)
        self.assertIn('root.querySelector',new)
        self.assertIn('scenarioPrice',new)
        listing = (self.root/'components/projects/v1.2.0/index.html').read_text(encoding='utf-8')
        self.assertIn('../../stock-project/v1.1.0/index.html#work',listing)
        self.assertNotIn('../../stock-demo/',listing)


class VarcoReleaseTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[1] / 'docs'

    def test_approved_content_and_narrow_video_exception(self):
        page = (self.root/'components/varco-project/v1.0.0/index.html').read_text(encoding='utf-8')
        for text in ('City Of Rubble','Duskore','95개','외부 텍스처','소개 문구 작성 예정','프로그래밍을 제외한 제작 전반','우수상'):
            self.assertIn(text,page)
        self.assertEqual(page.count('<iframe '),1)
        self.assertNotIn('<script',page)
        self.assertIn('https://www.youtube.com/watch?v=QewprwQ5BGc',page)
        self.assertIn('referrerpolicy="strict-origin-when-cross-origin"',page)
        self.assertEqual(page.count('<section aria-labelledby='),5)
        listing = (self.root/'components/projects/v1.3.0/index.html').read_text(encoding='utf-8')
        self.assertEqual(listing.count('class="project-card"'),3)
        self.assertIn('../../stock-project/v1.1.0/index.html#work',listing)
        self.assertIn('../../varco-project/v1.0.0/index.html',listing)


class ReviewedImageTests(unittest.TestCase):
    root=Path(__file__).resolve().parents[1]
    route='components/heros-chef-project/v1.1.0/index.html'

    def setUp(self):
        self.policy=json.loads((self.root/'policy.json').read_text(encoding='utf-8'))
        self.html=(self.root/'docs'/self.route).read_text(encoding='utf-8')
        self.asset='assets/heros-chef/v1.0.0/main.png'
        self.data=(self.root/'docs'/self.asset).read_bytes()

    def test_image_permissions_are_exact_and_require_accessible_layout(self):
        validate_html(self.html,self.policy,route=self.route)
        for changed in (self.html.replace('../../../assets/heros-chef/v1.0.0/main.png','https://example.com/main.png'),self.html.replace('../../../assets/heros-chef/v1.0.0/main.png','../../../assets/heros-chef/v1.0.0/unreviewed.png'),self.html.replace('width="1280"','width="1279"'),self.html.replace('decoding="async"','onload="alert(1)"'),re.sub(r'alt="[^"]*"','alt=""',self.html),self.html.replace("img-src 'self'","img-src *")):
            with self.subTest(changed=changed[:20]),self.assertRaises(SecurityError):validate_html(changed,self.policy,route=self.route)
        with self.assertRaises(SecurityError):validate_html(self.html,self.policy,route='index.html')
        self.assertIn("img-src 'none'",page_csp(self.policy,'components/unapproved/v1.0.0/index.html'))

    def test_binary_hash_and_private_metadata_are_checked(self):
        import struct,zlib
        meta=self.policy['approved_image_assets'][self.asset]
        validate_image(self.data,self.asset,meta)
        with self.assertRaises(SecurityError):validate_image(self.data+b'extra',self.asset,meta)
        payload=b'tEXt'+b'Author\x00private';chunk=struct.pack('>I',len(payload)-4)+payload+struct.pack('>I',zlib.crc32(payload)&0xffffffff)
        changed=self.data[:33]+chunk+self.data[33:]
        with self.assertRaises(SecurityError):validate_image(changed,self.asset,{**meta,'sha256':hashlib.sha256(changed).hexdigest()})

    def test_unregistered_binary_and_tampered_history_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); target=root/'docs'/self.route;target.parent.mkdir(parents=True)
            target.write_text(self.html,encoding='utf-8',newline='\n')
            policy=dict(self.policy)
            policy['approved_inline_scripts']={};policy['approved_youtube_embeds']={}
            (root/'policy.json').write_text(json.dumps(policy),encoding='utf-8')
            for name in policy['approved_image_assets']:
                asset=root/'docs'/name;asset.parent.mkdir(parents=True,exist_ok=True);asset.write_bytes((self.root/'docs'/name).read_bytes())
            (root/'docs/catalog.json').write_text(json.dumps({'pages':[{'path':self.route,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}]}),encoding='utf-8')
            # The full page has navigation; history validation checks route-scoped approvals without requiring unrelated pages.
            def git(*args):subprocess.run(['git','-c','safe.directory='+root.as_posix(),*args],cwd=root,check=True,capture_output=True)
            git('init','--initial-branch=main');git('config','user.name','Review test');git('config','user.email','review'+'@example.invalid');git('add','.');git('commit','-m','Reviewed images')
            self.assertEqual(validate_outgoing_history(root)['outgoing_commits_checked'],1)
            (root/'docs'/self.asset).write_bytes(self.data+b'tampered');git('add','.');git('commit','-m','Tampered image')
            with self.assertRaises(SecurityError):validate_outgoing_history(root)
            with self.assertRaises(SecurityError):validate_repository(root)

    def test_chef_content_and_three_full_size_images(self):
        old=(self.root/'docs/components/heros-chef-project/v1.0.3/index.html').read_text(encoding='utf-8')
        for anchor in ('idea','environment','work','comment'):
            pattern=r'<section aria-labelledby="'+anchor+r'">.*?</section>'
            self.assertEqual(re.search(pattern,old,re.S)[0],re.search(pattern,self.html,re.S)[0])
        self.assertEqual(self.html.count('<img '),3)
        self.assertEqual(self.html.count('class="screenshot screenshot-hero"'),1)
        self.assertIn('object-fit:contain',self.html)
        self.assertIn('grid-template-columns:minmax(0,1fr)',self.html)


class ProfileCareerTests(unittest.TestCase):
    root=Path(__file__).resolve().parents[1]/'docs'

    def test_original_facts_preserved_and_links_are_cards(self):
        old=(self.root/'components/profile/v1.0.3/index.html').read_text(encoding='utf-8')
        new=(self.root/'components/profile/v1.1.0/index.html').read_text(encoding='utf-8')
        for anchor in ('education','qualifications'):
            pattern=r'<section aria-labelledby="'+anchor+'">.*?</section>'
            self.assertEqual(re.search(pattern,old,re.S)[0],re.search(pattern,new,re.S)[0])
        self.assertEqual(re.findall(r'<div class="period">(.*?)</div>',old),re.findall(r'<div class="period">(.*?)</div>',new))
        self.assertEqual(new.count('<a class="reference-card"'),2)
        for item in ('Introducing Skill Blitz_B','YouTube · BORA','매치 퍼즐 하우스','Google Play · mobirix','총 6종 기획','국내 이용 불가','서비스 종료','Project-ST','미출시','담당반 팀 프로젝트 관리'):
            self.assertIn(item,new)
        for forbidden in ('<iframe','<video','<script','<img','src='):
            self.assertNotIn(forbidden,new)
        self.assertIn(CSP,new)

    def test_project_bodies_are_not_changed_by_profile_entry_update(self):
        old=(self.root/'components/projects/v1.4.0/index.html').read_text(encoding='utf-8')
        new=(self.root/'components/projects/v1.5.0/index.html').read_text(encoding='utf-8')
        self.assertEqual(new,old.replace('../../profile/v1.0.3/','../../profile/v1.1.0/'))


class VarcoSubtitleTests(unittest.TestCase):
    def test_only_subtitle_font_and_navigation_changed(self):
        root=Path(__file__).resolve().parents[1]/'docs'
        old=(root/'components/varco-project/v1.0.0/index.html').read_text(encoding='utf-8')
        new=(root/'components/varco-project/v1.0.1/index.html').read_text(encoding='utf-8')
        expected=old.replace('</style>','.subtitle{font-variant-numeric:lining-nums}\n</style>').replace('../../projects/v1.3.0/','../../projects/v1.5.1/').replace('../../profile/v1.0.3/','../../profile/v1.1.0/')
        self.assertEqual(new,expected)
        listing=(root/'components/projects/v1.5.0/index.html').read_text(encoding='utf-8')
        self.assertEqual((root/'components/projects/v1.5.1/index.html').read_text(encoding='utf-8'),listing.replace('../../varco-project/v1.0.0/','../../varco-project/v1.0.1/'))


if __name__ == "__main__":
    unittest.main()


class ScopedWebfontTests(unittest.TestCase):
    route = 'components/font-review/v1.0.0/index.html'
    def policy(self):
        return {**POLICY, 'approved_webfonts': {self.route: ['chosun-bold', 'chosun-shin']}}
    def html(self):
        return page(style=font_css('chosun-bold')+font_css('chosun-shin')).replace(CSP,page_csp(self.policy(),self.route))
    def test_exact_fonts_and_unchanged_legacy_csp(self):
        validate_html(self.html(),self.policy(),route=self.route)
        self.assertEqual(page_csp(self.policy(),'components/old/v1.0.0/index.html'),CSP)
    def test_font_source_and_route_changes_rejected(self):
        for html in [self.html().replace('ChosunKm.woff','Other.woff'),self.html().replace('ChosunKm.woff','ChosunKm.woff?x=1'),self.html().replace('font-display:swap','font-display:block')]:
            with self.assertRaises(SecurityError):validate_html(html,self.policy(),route=self.route)
        with self.assertRaises(SecurityError):validate_html(self.html(),self.policy(),route='components/other/v1.0.0/index.html')
    def test_missing_duplicate_and_extra_resource_rejected(self):
        for html in [self.html().replace(font_css('chosun-bold'),''),self.html().replace('</style>',font_css('chosun-bold')+'</style>'),self.html().replace('</style>','p{background:url(https://example.com/x)}</style>')]:
            with self.assertRaises(SecurityError):validate_html(html,self.policy(),route=self.route)
    def test_broad_csp_rejected(self):
        html=self.html().replace('font-src https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_20-04@1.0/ChosunKm.woff https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_20-04@1.1/ChosunSm.woff','font-src https:')
        with self.assertRaises(SecurityError):validate_html(html,self.policy(),route=self.route)
