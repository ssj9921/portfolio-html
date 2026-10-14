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
from check_public import CSP, SecurityError, validate_html, validate_repository, validate_outgoing_history

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


class PortfolioMigrationTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[1]
    project = "components/heros-chef-project/v1.0.2/index.html"
    profile = "components/profile/v1.0.2/index.html"
    projects = "components/projects/v1.0.0/index.html"

    def test_complete_public_export_passes(self):
        result = validate_repository(self.root)
        self.assertTrue(result["valid"])
        self.assertEqual(result["html_pages"], 14)

    def test_four_primary_pages_use_internal_navigation(self):
        home = (self.root / "docs/index.html").read_text(encoding="utf-8")
        for route in (self.project, self.profile, self.projects):
            self.assertIn('href="' + route + '"', home)
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
        self.assertIn('href="' + self.projects + '">Projects</a>', home)
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


if __name__ == "__main__":
    unittest.main()
