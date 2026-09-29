"""Mocked public-feed regressions: no network access or API keys required."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse
from urllib.request import Request

from app import connectors as c
from app.intelligence import match_version


NOW = datetime.now(timezone.utc).replace(microsecond=0)
RECENT = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
SINCE = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")


def source(kind: str, keywords: list[str] | None = None, **extra: object) -> dict:
    urls = {"nvd": c.NVD_URL, "github_advisories": c.GITHUB_URL,
            "cisa_kev": c.CISA_URL, "rss": "https://example.org/feed.xml",
            "static_html": "https://example.org/policy", "osv": c.OSV_URL}
    configured = {"id": kind, "type": kind, "url": urls[kind], "category": kind,
                  "enabled": True, "keywords": keywords or ["ollama"]}
    configured.update(extra)
    return configured


def cve(cve_id: str, configs: list[dict] | None = None, **extra: object) -> dict:
    return {"cve": {"id": cve_id, "published": RECENT, "lastModified": RECENT,
                    "descriptions": [{"lang": "en", "value": "Ollama security issue"}],
                    "references": [{"url": "https://vendor.example/advisory"}],
                    "configurations": configs or [], **extra}}


def cpe(product: str, end: str) -> dict:
    return {"vulnerable": True,
            "criteria": f"cpe:2.3:a:vendor:{product}:*:*:*:*:*:*:*:*",
            "versionEndExcluding": end}


class ConnectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pacer = patch.object(c, "_pace_nvd", return_value=None)
        self.pacer.start()
        self.addCleanup(self.pacer.stop)

    def test_nvd_keeps_product_ranges_separate_and_filters_links(self) -> None:
        entry = cve("CVE-2026-12345", [{"operator": "OR", "nodes": [
            {"operator": "OR", "cpeMatch": [cpe("ollama", "0.6.0"),
                                            cpe("langchain", "0.3.0")]}]}])
        entry["cve"]["references"].extend([
            {"url": "javascript:alert(1)"}, {"url": "https://127.0.0.1/secret"}])
        with patch.object(c, "_get_json", return_value=(
                {"totalResults": 1, "vulnerabilities": [entry]}, {})) as get:
            rows = c.fetch_source(source("nvd", ["ollama"]))
        self.assertEqual([(r["product"], r["versions"]) for r in rows],
                         [("ollama", ["<0.6.0"]), ("langchain", ["<0.3.0"])])
        self.assertEqual(len({r["external_id"] for r in rows}), 2)
        self.assertEqual(rows[0]["identifiers"], ["CVE-2026-12345"])
        self.assertEqual(rows[0]["refs"], ["https://vendor.example/advisory"])
        query = parse_qs(urlparse(get.call_args.args[0]).query)
        self.assertEqual(query["keywordSearch"], ["ollama"])
        self.assertIn("lastModStartDate", query)
        self.assertIn("lastModEndDate", query)

    def test_nvd_conditional_and_cpe_does_not_claim_version_impact(self) -> None:
        entry = cve("CVE-2026-12345", [{"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": [cpe("ollama", "0.6.0")]}]}])
        with patch.object(c, "_get_json", return_value=(
                {"totalResults": 1, "vulnerabilities": [entry]}, {})):
            rows = c.fetch_source(source("nvd"))
        self.assertEqual(rows[0]["product"], "ollama")
        self.assertEqual(rows[0]["versions"], [])

    def test_nvd_uses_cna_affected_when_cpe_unavailable(self) -> None:
        entry = cve("CVE-2026-12345", affected=[{"source": "cna", "affectedData": [
            {"product": "Ollama", "versions": [
                {"version": "0", "lessThan": "0.6.0", "status": "affected"},
                {"version": "0.6.0", "status": "unaffected"}]}]}])
        with patch.object(c, "_get_json", return_value=(
                {"totalResults": 1, "vulnerabilities": [entry]}, {})):
            rows = c.fetch_source(source("nvd"))
        self.assertEqual(rows[0]["product"], "Ollama")
        self.assertEqual(rows[0]["versions"], [">=0, <0.6.0"])

    def test_nvd_paginates_and_fails_closed_on_limit(self) -> None:
        entries = [cve("CVE-2026-12345"), cve("CVE-2026-12346")]
        calls: list[int] = []

        def response(url: str, **_: object) -> tuple[dict, dict]:
            offset = int(parse_qs(urlparse(url).query)["startIndex"][0])
            calls.append(offset)
            return {"totalResults": 2, "vulnerabilities": entries[offset:offset + 1]}, {}

        with patch.object(c, "_get_json", side_effect=response):
            with self.assertRaisesRegex(c.ConnectorError, "more than 1"):
                c.fetch_source(source("nvd"), limit=1)
        self.assertEqual(calls, [0, 1])

    def test_github_separates_packages_and_avoids_ambiguous_ecosystem(self) -> None:
        advisory = {"ghsa_id": "GHSA-abcd-1234-efgh", "cve_id": "CVE-2026-12345",
                    "summary": "Ollama advisory", "description": "Ollama issue",
                    "updated_at": RECENT, "published_at": RECENT,
                    "html_url": "javascript:alert(1)",
                    "references": ["https://vendor.example/fix", "http://127.0.0.1/admin"],
                    "vulnerabilities": [
                        {"package": {"name": "ollama", "ecosystem": "pip"},
                         "vulnerable_version_range": "<1.0", "first_patched_version": "1.0"},
                        {"package": {"name": "ollama", "ecosystem": "npm"},
                         "vulnerable_version_range": "<2.0", "first_patched_version": "2.0"},
                        {"package": {"name": "langchain", "ecosystem": "pip"},
                         "vulnerable_version_range": "<0.3", "first_patched_version": "0.3"}]}
        with patch.object(c, "_get_json", return_value=([advisory], {})) as get:
            rows = c.fetch_source(source("github_advisories"), since=SINCE)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["product"], "ollama")
        self.assertEqual(rows[0]["versions"], [])
        self.assertEqual(rows[0]["fixed_versions"], [])
        self.assertEqual(rows[1]["versions"], ["<0.3"])
        self.assertEqual(rows[0]["url"], "https://github.com/advisories/GHSA-abcd-1234-efgh")
        self.assertEqual(rows[0]["refs"], ["https://vendor.example/fix"])
        query = parse_qs(urlparse(get.call_args.args[0]).query)
        self.assertEqual(query["modified"], [">=" + (NOW - timedelta(days=1)).isoformat(timespec="seconds")])

    def test_github_follows_bounded_filtered_pagination(self) -> None:
        advisory = {"ghsa_id": "GHSA-abcd-1234-efgh", "summary": "Ollama issue",
                    "description": "Ollama issue", "updated_at": RECENT,
                    "vulnerabilities": [{"package": {"name": "ollama"},
                                         "vulnerable_version_range": "<1.0"}]}
        requested: list[str] = []

        def response(url: str, **_: object) -> tuple[list, dict]:
            requested.append(url)
            if "after=cursor" in url:
                return [advisory], {}
            return [], {"Link": f'<{url}&after=cursor>; rel="next"'}

        with patch.object(c, "_get_json", side_effect=response):
            rows = c.fetch_source(source("github_advisories"), since=SINCE)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(requested), 2)

    def test_kev_catalog_release_does_not_mutate_unchanged_record(self) -> None:
        item = {"cveID": "CVE-2026-12345", "vendorProject": "Ollama",
                "product": "Ollama", "vulnerabilityName": "Ollama issue",
                "dateAdded": "2026-09-01", "shortDescription": "Ollama vulnerability",
                "requiredAction": "Update", "dueDate": "2026-10-01"}
        payload = {"vulnerabilities": [item], "dateReleased": RECENT}
        with patch.object(c, "_get_json", return_value=(payload, {})):
            first = c.fetch_source(source("cisa_kev"), since=SINCE)
        payload["dateReleased"] = NOW.isoformat()
        with patch.object(c, "_get_json", return_value=(payload, {})):
            second = c.fetch_source(source("cisa_kev"), since=SINCE)
        self.assertEqual(first, second)
        self.assertTrue(first[0]["raw"]["known_exploited"])

    def test_atom_xhtml_and_changed_old_entry_are_reconciled(self) -> None:
        old = (NOW - timedelta(days=30)).isoformat().replace("+00:00", "Z")
        feed = f'''<feed xmlns="http://www.w3.org/2005/Atom">
          <entry><id>tag:example.org,1</id><title>Ollama research</title>
            <updated>{old}</updated><link rel="alternate" href="javascript:alert(1)"/>
            <content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">
              <p>Ollama</p><p>security study</p></div></content></entry>
          </feed>'''.encode()
        with patch.object(c, "_http_get", return_value=(feed, {})):
            rows = c.fetch_source(source("rss", category="paper"), since=SINCE)
        self.assertEqual(len(rows), 1)
        self.assertIn("Ollama security study", rows[0]["body"])
        self.assertEqual(rows[0]["url"], "https://example.org/feed.xml")
        self.assertEqual(rows[0]["kind"], "paper")

    def test_rss_rejects_dtd(self) -> None:
        data = b'<!DOCTYPE feed [<!ENTITY x "bad">]><rss><channel/></rss>'
        with patch.object(c, "_http_get", return_value=(data, {})):
            with self.assertRaisesRegex(c.ConnectorError, "forbidden DTD"):
                c.fetch_source(source("rss"))

    def test_rss_permalink_guid_is_used_when_link_is_absent(self) -> None:
        feed = b'''<rss version="2.0"><channel><item>
          <guid isPermaLink="true">https://huggingface.co/blog/ollama-security</guid>
          <title>Ollama security update</title><description>Ollama issue</description>
          </item></channel></rss>'''
        with patch.object(c, "_http_get", return_value=(feed, {})):
            rows = c.fetch_source(source("rss"))
        self.assertEqual(rows[0]["url"], "https://huggingface.co/blog/ollama-security")

    def test_static_html_uses_url_identity_and_content_hash(self) -> None:
        config = source("static_html", ["生成式人工智能"], category="policy")
        def page(text: str) -> bytes:
            return (f'<html><head><meta charset="gb2312"><title>生成式人工智能管理办法</title>'
                    f'</head><body><main><p>{text}</p></main></body></html>').encode("gb18030")
        headers = {"Last-Modified": "Tue, 29 Sep 2026 00:00:00 GMT"}
        with patch.object(c, "_http_get", return_value=(page("生成式人工智能安全要求"), headers)):
            first = c.fetch_source(config)[0]
        with patch.object(c, "_http_get", return_value=(page("生成式人工智能更新要求"), headers)):
            second = c.fetch_source(config)[0]
        self.assertEqual(first["external_id"], config["url"])
        self.assertEqual(second["external_id"], config["url"])
        self.assertNotEqual(first["raw"]["content_sha256"], second["raw"]["content_sha256"])
        self.assertEqual(second["kind"], "policy")
        self.assertIn("生成式人工智能", second["body"])

    def test_source_url_and_record_link_safety(self) -> None:
        for url in ("http://example.org/feed", "https://127.0.0.1/secret",
                    "https://user:pass@example.org/feed", "file:///etc/passwd"):
            with self.subTest(url=url), self.assertRaises(c.ConnectorError):
                c._validated_url(url)
        self.assertEqual(c._safe_reference("javascript:alert(1)"), "")
        self.assertEqual(c._safe_reference("//127.0.0.1/secret",
                                           base="https://example.org/feed"), "")
        authenticated = Request("https://api.github.com/advisories",
                                headers={"Authorization": "Bearer secret"})
        with self.assertRaisesRegex(c.ConnectorError, "may not redirect"):
            c._SafeRedirect().redirect_request(authenticated, None, 302, "Found", {},
                                               "https://attacker.example/advisories")

    def test_disabled_source_never_fetches(self) -> None:
        with patch.object(c, "_http_get") as get:
            self.assertEqual(c.fetch_source(source("rss", enabled=False)), [])
        get.assert_not_called()

    def test_osv_maps_packages_ranges_and_cve_alias(self) -> None:
        advisory = {
            "id": "GHSA-v4fg-8ghg-7whh8", "aliases": ["CVE-2024-37032"],
            "summary": "Ollama digest validation bypass",
            "details": "Ollama before 0.1.34 does not validate the digest format.",
            "published": RECENT, "modified": RECENT,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "ollama"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [
                              {"introduced": "0"}, {"fixed": "0.1.34"}]}]}],
            "references": [{"type": "WEB", "url": "https://github.com/advisories/GHSA-v4fg-8ghh-7whh8"}],
        }
        config = source("osv", ["ollama"], packages=["pypi:ollama"])
        with patch.object(c, "_post_json", return_value=({"vulns": [advisory]}, {})) as post:
            rows = c.fetch_source(config)
        self.assertEqual(post.call_args.args[1],
                         {"package": {"ecosystem": "PyPI", "name": "ollama"}})
        row = rows[0]
        from app.intelligence import normalize_record
        self.assertEqual(normalize_record(row)["canonical_id"], "CVE-2024-37032")
        self.assertEqual(row["product"], "ollama")
        self.assertEqual(row["versions"], ["<0.1.34"])
        self.assertEqual(row["fixed_versions"], ["0.1.34"])
        self.assertEqual(row["cvss"], 9.8)
        self.assertEqual(row["severity"], "CRITICAL")
        self.assertIn("CVE-2024-37032", row["identifiers"])
        self.assertEqual(row["url"], "https://osv.dev/vulnerability/GHSA-v4fg-8ghg-7whh8")

    def test_osv_does_not_expand_redundant_release_enumerations(self) -> None:
        affected = {"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.83.7"}]}],
            "versions": [f"1.{minor}.0" for minor in range(80)]}
        self.assertEqual(c._osv_version_ranges(affected), ["<1.83.7"])
        affected["versions"].extend(["1.83.7", "1.0rc1"])
        self.assertEqual(c._osv_version_ranges(affected),
                         ["<1.83.7", "==1.83.7", "==1.0rc1"])
        prerelease = {"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.8.0rc2"}]}],
            "versions": ["1.7.3"]}
        self.assertEqual(c._osv_version_ranges(prerelease),
                         ["<1.8.0rc2", "==1.7.3"])
        self.assertEqual(match_version("1.7.3", c._osv_version_ranges(prerelease), []),
                         "affected")
        mixed = {"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "2.0"},
            {"introduced": "3.0rc1"}, {"fixed": "3.1rc1"}]}],
            "versions": ["1.5", "2.5"]}
        self.assertEqual(c._osv_version_ranges(mixed),
                         ["<2.0", ">=3.0rc1, <3.1rc1", "==2.5"])
        open_ended = {"ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}]}]}
        self.assertEqual(c._osv_version_ranges(open_ended), [">=0"])
        self.assertEqual(match_version("0.10.0", c._osv_version_ranges(open_ended), []),
                         "affected")
        self.assertEqual(c._osv_version_ranges({"versions": ["0.1", "0.2"]}),
                         ["==0.1", "==0.2"])

    def test_cvss3_base_score_matches_first_reference_values(self) -> None:
        self.assertEqual(c.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                         (9.8, "CRITICAL"))
        self.assertEqual(c.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
                         (10.0, "CRITICAL"))
        self.assertEqual(c.cvss3_base_score("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                         (3.7, "LOW"))
        self.assertEqual(c.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L"),
                         (7.1, "HIGH"))
        self.assertIsNone(c.cvss3_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"))

    def test_osv_rejects_unknown_host_and_bad_package(self) -> None:
        with self.assertRaisesRegex(c.ConnectorError, "api.osv.dev"):
            c.fetch_source({"id": "osv", "type": "osv", "category": "osv",
                            "url": "https://evil.example/v1/query", "enabled": True,
                            "keywords": ["ollama"], "packages": ["pypi:ollama"]})
        with patch.object(c, "_post_json", return_value=({"vulns": []}, {})):
            with self.assertRaisesRegex(c.ConnectorError, "ecosystem:name"):
                c.fetch_source({"id": "osv", "type": "osv", "category": "osv",
                                "url": c.OSV_URL, "enabled": True,
                                "keywords": ["ollama"], "packages": ["ollama"]})
            with self.assertRaisesRegex(c.ConnectorError, "supported map"):
                c.fetch_source({"id": "osv", "type": "osv", "category": "osv",
                                "url": c.OSV_URL, "enabled": True,
                                "keywords": ["ollama"], "packages": ["perl:ollama"]})

    def test_osv_pagination_is_complete_or_fails_without_silent_truncation(self) -> None:
        def advisory(identifier: str) -> dict:
            return {"id": identifier, "summary": "Ollama package vulnerability",
                    "modified": RECENT, "affected": [
                        {"package": {"ecosystem": "PyPI", "name": "ollama"},
                         "ranges": [{"type": "ECOSYSTEM", "events": [
                             {"introduced": "0"}, {"fixed": "1.0"}]}]}]}

        requested: list[dict] = []
        def response(_url: str, payload: dict, **_: object) -> tuple[dict, dict]:
            requested.append(payload)
            if payload.get("page_token") == "page-two":
                return {"vulns": [advisory("GHSA-2222-bbbb-cccc")]}, {}
            return {"vulns": [advisory("GHSA-1111-aaaa-bbbb")],
                    "next_page_token": "page-two"}, {}

        config = source("osv", packages=["pypi:ollama"])
        with patch.object(c, "_post_json", side_effect=response):
            rows = c.fetch_source(config, limit=2)
            with self.assertRaisesRegex(c.ConnectorError, "more than 1"):
                c.fetch_source(config, limit=1)
        self.assertEqual(len(rows), 2)
        self.assertEqual(requested[1]["page_token"], "page-two")

    def test_osv_external_identity_survives_later_cve_alias(self) -> None:
        advisory = {"id": "GHSA-1111-aaaa-bbbb", "summary": "Ollama issue",
                    "modified": RECENT, "affected": [
                        {"package": {"ecosystem": "PyPI", "name": "ollama"},
                         "versions": ["0.1.0"]}]}
        config = source("osv", packages=["pypi:ollama"])
        with patch.object(c, "_post_json", return_value=({"vulns": [advisory]}, {})):
            before = c.fetch_source(config)[0]
        advisory["aliases"] = ["CVE-2026-12345"]
        with patch.object(c, "_post_json", return_value=({"vulns": [advisory]}, {})):
            after = c.fetch_source(config)[0]
        self.assertEqual(before["external_id"], after["external_id"])
        self.assertIn("CVE-2026-12345", after["identifiers"])
        self.assertEqual(after["versions"], ["==0.1.0"])

    def test_osv_accepts_native_database_id_with_cve_alias(self) -> None:
        advisory = {"id": "PYSEC-2026-123", "aliases": ["CVE-2026-12345"],
                    "summary": "Ollama issue", "modified": RECENT,
                    "affected": [{"package": {"ecosystem": "PyPI", "name": "ollama"},
                                  "versions": ["0.1.0"]}]}
        with patch.object(c, "_post_json", return_value=({"vulns": [advisory]}, {})):
            row = c.fetch_source(source("osv", packages=["pypi:ollama"]))[0]
        self.assertTrue(row["external_id"].startswith("PYSEC-2026-123::"))
        self.assertIn("CVE-2026-12345", row["identifiers"])

    def test_osv_keeps_disjoint_ranges_and_ignores_other_ecosystems(self) -> None:
        affected = {"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.0"},
            {"introduced": "2.0"}, {"fixed": "3.0"},
            {"introduced": "4.0"}]},
            {"type": "GIT", "events": [
                {"introduced": "0123abcd"}, {"fixed": "deadbeef"}]}]}
        self.assertEqual(c._osv_version_ranges(affected),
                         ["<1.0", ">=2.0, <3.0", ">=4.0"])
        advisory = {"id": "GHSA-1111-aaaa-bbbb", "summary": "Ollama issue",
                    "modified": RECENT, "affected": [
                        {"package": {"ecosystem": "npm", "name": "ollama"}, **affected}]}
        with patch.object(c, "_post_json", return_value=({"vulns": [advisory]}, {})):
            self.assertEqual(c.fetch_source(source("osv", packages=["pypi:ollama"])), [])

    def test_epss_batches_requests_and_skips_unknown_cves(self) -> None:
        def fake_get(url: str, **_: object) -> tuple[dict, dict]:
            self.assertIn("cve=CVE-2021-44228", url)
            return {"data": [{"cve": "CVE-2021-44228", "epss": "0.97",
                              "percentile": "0.99", "date": "2026-09-28"}]}, {}
        with patch.object(c, "_get_json", side_effect=fake_get):
            scores = c.fetch_epss(["CVE-2021-44228", "CVE-2099-00001", "junk"])
        self.assertEqual(scores["CVE-2021-44228"]["epss"], 0.97)
        self.assertNotIn("CVE-2099-00001", scores)


if __name__ == "__main__":
    unittest.main()
