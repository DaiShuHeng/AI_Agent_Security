"""Regressions for durable live ingestion and indexed evidence lookup."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.db import Database
from app.pipeline import Pipeline


SOURCE = {
    "id": "live_nvd", "type": "nvd", "category": "nvd",
    "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "enabled": True, "keywords": ["ollama"],
}
RECORD = {
    "external_id": "CVE-2026-12345::ollama",
    "title": "CVE-2026-12345 Ollama vulnerability",
    "summary": "Ollama security issue", "body": "Ollama security issue",
    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
    "published_at": "2026-09-28T01:00:00Z",
    "updated_at": "2026-09-28T02:00:00Z",
    "source_id": "live_nvd", "source_category": "nvd",
    "kind": "vulnerability", "identifiers": ["CVE-2026-12345", "GHSA-1111-aaaa-bbbb"],
    "product": "ollama", "cvss": 8.8, "severity": "HIGH",
    "versions": ["<0.6.0"], "fixed_versions": ["0.6.0"],
    "refs": ["https://example.org/security-advisory"], "raw": {},
}


class PipelineIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Database(Path(self.temp.name) / "intel.sqlite3")
        self.pipeline = Pipeline(self.db, sources=[SOURCE])

    def test_source_reconfiguration_resets_only_changed_cursor(self) -> None:
        cursor = "2026-09-28T12:00:00+00:00"
        self.db.source_status(SOURCE["id"], success=True, cursor=cursor)
        self.db.configure_sources([dict(SOURCE)])
        self.assertEqual(self.db.source_rows()[0]["cursor"], cursor)
        changed = dict(SOURCE, keywords=["langflow"])
        self.db.configure_sources([changed])
        row = self.db.source_rows()[0]
        self.assertIsNone(row["cursor"])
        self.assertIsNone(row["last_success"])
        self.assertEqual(row["status"], "idle")

    def test_live_retry_restores_partially_written_claims(self) -> None:
        original = self.db.add_claim
        calls = 0

        def fail_once(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("transient disk error")
            original(*args, **kwargs)

        with patch.object(self.db, "add_claim", side_effect=fail_once), \
             patch("app.connectors.fetch_source", return_value=[dict(RECORD)]), \
             patch.object(self.pipeline, "_enrich_epss", return_value=0), \
             patch("app.pipeline.time.sleep", return_value=None):
            result = self.pipeline.run_live()
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(self.db.document_group("CVE-2026-12345")), 1)
        predicates = {claim["predicate"] for claim in self.db.claims("CVE-2026-12345")}
        self.assertTrue({"affects_product", "cvss", "severity", "affected_version",
                         "fixed_version", "alias", "reference"} <= predicates)
        self.assertEqual(self.db.source_rows()[0]["status"], "healthy")

    def test_cursor_is_collection_start_not_processing_end(self) -> None:
        started = "2026-09-29T00:00:00+00:00"
        with patch("app.connectors.fetch_source", return_value=[]), \
             patch("app.pipeline.utcnow", return_value=started), \
             patch.object(self.pipeline, "_enrich_epss", return_value=0):
            result = self.pipeline.run_live()
        self.assertEqual(result["status"], "success")
        self.assertEqual(self.db.source_rows()[0]["cursor"], started)

    def test_alias_lookup_uses_entire_claim_index(self) -> None:
        run_id = self.db.create_run("live")
        self.pipeline._ingest(dict(RECORD), run_id)
        document_id = self.db.document_group("CVE-2026-12345")[0]["id"]
        for number in range(550):
            self.db.add_claim("unrelated", "reference", f"https://example.org/{number}",
                              document_id, "fixture", 0.5)
        self.assertEqual(self.db.canonical_for_alias("ghsa-1111-aaaa-bbbb"),
                         "CVE-2026-12345")
        self.assertEqual(self.db.canonical_for_alias("CVE-2026-12345"),
                         "CVE-2026-12345")
        self.db.add_claim("CVE-2026-99999", "alias", "GHSA-1111-AAAA-BBBB",
                          document_id, "conflicting fixture", 0.5)
        self.assertIsNone(self.db.canonical_for_alias("GHSA-1111-aaaa-bbbb"))

    def test_vulnerability_pages_and_dynamic_products(self) -> None:
        run_id = self.db.create_run("live")
        self.pipeline._ingest(dict(RECORD, product="ollama"), run_id)
        for number in range(201):
            record = dict(RECORD, external_id=f"CVE-2026-{20000 + number}::langflow",
                          title=f"CVE-2026-{20000 + number} Langflow issue",
                          identifiers=[f"CVE-2026-{20000 + number}"],
                          product="langflow", refs=[])
            self.pipeline._ingest(record, run_id)
        page1 = self.db.vulnerability_documents(limit=200, offset=0)
        page2 = self.db.vulnerability_documents(limit=200, offset=200)
        self.assertEqual((len(page1), len(page2)), (200, 2))
        self.assertEqual(len({row["id"] for row in page1 + page2}), 202)
        self.assertIn("langflow", self.db.known_products())
        self.assertIn("ollama", self.db.known_products())

    def test_vulnerability_id_requires_exact_format_and_osv_native_provenance(self) -> None:
        run_id = self.db.create_run("live")
        invalid = dict(RECORD, external_id="CVE-fake", title="CVE-fake Ollama issue",
                       identifiers=[])
        self.assertEqual(self.pipeline._ingest(invalid, run_id), "skipped")
        self.assertEqual(self.db.stats()["documents"], 0)

        osv_source = dict(SOURCE, id="osv_native", type="osv", category="osv",
                          url="https://api.osv.dev/v1/query")
        osv_pipeline = Pipeline(self.db, sources=[osv_source])
        native = dict(RECORD, external_id="PYSEC-2026-123::PyPI:ollama",
                      title="PYSEC-2026-123 Ollama issue", identifiers=["PYSEC-2026-123"],
                      source_id="osv_native", source_category="osv",
                      url="https://osv.dev/vulnerability/PYSEC-2026-123",
                      raw={"id": "PYSEC-2026-123"})
        self.assertEqual(osv_pipeline._ingest(native, run_id), "inserted")
        self.assertEqual(len(self.db.document_group("PYSEC-2026-123")), 1)


if __name__ == "__main__":
    unittest.main()
