"""Tests for the security and correctness boundaries of the offline core."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from app.db import Database
from app.intelligence import asset_impacts, match_version, normalize_record
from app.pipeline import Pipeline, load_demo_records
from app.qa import AnswerEngine


SURVEY_RECORD = {
    "external_id": "survey-llm-infra-security-2025",
    "title": "LLM 推理框架供应链安全综述（单元测试样例）",
    "summary": "综述整理了大模型推理组件的典型漏洞披露流程。",
    "body": "文章回顾了 llama-cpp-python 的 CVE-2024-34359 模板注入问题及其披露时间线。",
    "url": "https://example.invalid/survey-llm-infra",
    "published_at": "2025-02-01",
    "source_id": "survey_test",
    "source_category": "paper",
    "kind": "paper",
    "identifiers": [],
    "cvss": None,
    "severity": "",
    "versions": [],
    "fixed_versions": [],
    "refs": [],
    "raw": {"snapshot_type": "unit_test_fixture"},
}


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "test.sqlite3")
        self.pipeline = Pipeline(self.db, sources=[])

    def tearDown(self):
        self.temp.cleanup()

    def test_replay_is_idempotent_and_cross_source_cve_is_joined(self):
        first = self.pipeline.run_demo()
        replay = self.pipeline.run_demo()
        self.assertEqual(first["inserted"], 7)
        self.assertEqual(replay["skipped"], 7)
        self.assertEqual(self.db.stats()["vulnerabilities"], 3)
        self.assertEqual(len(self.db.document_group("CVE-2024-37032")), 2)

    def test_demo_does_not_reconfigure_live_source(self):
        source = {"id": "github_advisories", "type": "github_advisories",
                  "category": "github_advisories", "url": "https://api.github.com/advisories",
                  "enabled": True}
        self.db.configure_sources([source])
        self.pipeline.run_demo()
        row = next(row for row in self.db.source_rows() if row["id"] == source["id"])
        self.assertEqual(row["type"], "github_advisories")
        self.assertEqual(row["enabled"], 1)
        self.assertEqual(row["status"], "idle")

    def test_changed_source_updates_in_place_and_rebuilds_claims(self):
        record = copy.deepcopy(load_demo_records()[0])
        self.db.configure_sources([{"id": record["source_id"], "type": "demo",
                                    "category": record["source_category"], "url": record["url"]}])
        item = normalize_record(record)
        doc_id, state = self.db.upsert_document(item)
        self.assertEqual(state, "inserted")
        item["summary"] += " 来源更新。"
        same_id, state = self.db.upsert_document(item)
        self.assertEqual((same_id, state), (doc_id, "updated"))
        self.assertEqual(self.db.stats()["documents"], 1)

    def test_version_ranges_and_uncertainty(self):
        self.assertEqual(match_version("0.2.71", [">= 0.2.30", "<= 0.2.71"], ["0.2.72"]), "affected")
        self.assertEqual(match_version("0.2.72", [">= 0.2.30", "<= 0.2.71"], ["0.2.72"]), "not_affected")
        self.assertEqual(match_version("2.5", [">=1,<2", ">=2.5,<3"], []), "affected")
        self.assertEqual(match_version("beta", ["< 1.3.0"], ["1.3.0"]), "unknown")

    def test_no_cvss_does_not_become_zero_priority(self):
        self.pipeline.run_demo()
        impacts = asset_impacts(self.db, "CVE-2024-37032")
        self.assertEqual(impacts[0]["status"], "affected")
        self.assertIsNone(impacts[0]["priority"])
        self.assertIn("待评估", impacts[0]["priority_basis"])

    def test_answers_are_cited_and_unknown_cve_abstains(self):
        self.pipeline.run_demo()
        qa = AnswerEngine(self.db)
        answer = qa.ask("CVE-2024-37032 影响哪些资产？如何修复？")
        self.assertFalse(answer["abstained"])
        self.assertEqual({item["source_id"] for item in answer["citations"]},
                         {"github_advisories", "research_wiz"})
        self.assertTrue(any(item["via"] == "local_asset_version_match" for item in answer["trace"]))
        unknown = qa.ask("CVE-2099-99999 的修复版本是什么？")
        self.assertTrue(unknown["abstained"])
        self.assertEqual(unknown["citations"], [])

    def test_cross_document_mention_association(self):
        records = load_demo_records() + [SURVEY_RECORD]
        self.pipeline.run_demo(records=records)
        related = self.db.related_documents("CVE-2024-34359")
        self.assertEqual([doc["external_id"] for doc in related], [SURVEY_RECORD["external_id"]])
        events = [e for e in self.db.recent_events(200)
                  if e["agent"] == "关联推理代理" and e["status"] == "ok"]
        self.assertTrue(events, "关联推理代理事件应写入运行轨迹")
        qa = AnswerEngine(self.db)
        answer = qa.ask("CVE-2024-34359 相关研究论文有哪些？")
        self.assertFalse(answer["abstained"])
        survey_citation = next((c for c in answer["citations"]
                                if c["source_id"] == "survey_test"), None)
        self.assertIsNotNone(survey_citation)
        self.assertIn(f"[{survey_citation['number']}]", answer["answer"])
        self.assertTrue(any(item["via"] == "mentioned_in" for item in answer["trace"]))

    def test_collection_latency_stats_split_by_mode(self):
        self.pipeline.run_demo()
        stats = self.db.collection_latency_stats()
        self.assertEqual(stats["demo_snapshot"]["samples"], 7)
        self.assertEqual(stats["live"]["samples"], 0)
        self.assertGreater(stats["demo_snapshot"]["p50_hours"], 0)
        self.assertIsNone(stats["live"]["p50_hours"])

    def test_single_ai_term_record_passes_triage(self):
        # 单个 AI 术语命中得分 1/3≈0.333，必须通过 0.33 的分诊阈值：
        # 真实案例是标题仅含 "Agentic AI" 的社区公告与 smolagents 等框架 CVE。
        record = {
            "external_id": "agentic-ai-attack-advisory", "kind": "article",
            "title": "Agentic AI attacks target Azure tenants", "summary": "",
            "body": "", "url": "https://example.invalid/agentic",
            "source_id": "community_test", "source_category": "community",
        }
        self.assertGreaterEqual(normalize_record(record)["ai_score"], 0.33)
        self.db.configure_sources([{"id": "community_test", "type": "rss",
                                    "category": "community", "url": record["url"]}])
        run_id = self.db.create_run("live")
        state = self.pipeline._ingest(record, run_id=run_id)
        self.db.finish_run(run_id, "success", {})
        self.assertEqual(state, "inserted")

    def test_topic_switch_is_not_hijacked_by_session_context(self):
        self.pipeline.run_demo()
        qa = AnswerEngine(self.db)
        first = qa.ask("CVE-2024-34359 是什么？")
        switched = qa.ask("AI 安全领域有哪些政策法规？", session_id=first["session_id"])
        self.assertNotEqual(switched.get("canonical_id"), "CVE-2024-34359")
        self.assertIn("生成式人工智能", switched["answer"])
        followup = qa.ask("接着说，它影响哪些资产？", session_id=first["session_id"])
        self.assertEqual(followup.get("canonical_id"), "CVE-2024-34359")

    def test_portfolio_question_after_product_question_lists_all(self):
        self.pipeline.run_demo()
        qa = AnswerEngine(self.db)
        first = qa.ask("ollama 有什么漏洞？")
        portfolio = qa.ask("现在整个知识库有哪些高危漏洞？", session_id=first["session_id"])
        self.assertIsNone(portfolio.get("canonical_id"))
        self.assertIn("CVE-2024-34359", portfolio["answer"])

    def test_cjk_substring_search_fallback(self):
        self.pipeline.run_demo()
        # FTS5 unicode61 把整句中文当作单 token；子串查询必须走 LIKE 回退。
        rows = self.db.documents(query="管理办法")
        self.assertTrue(any("生成式人工智能" in (row["title"] + row["summary"]) for row in rows))
        rows = self.db.documents(query="提示词注入 论文")
        self.assertTrue(any(row["kind"] == "paper" for row in rows))


if __name__ == "__main__":
    unittest.main()
