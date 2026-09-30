"""Regressions for grounded answers beyond the hand-picked evaluation fixture."""

from __future__ import annotations

import tempfile
import unittest
import re
from pathlib import Path
from unittest.mock import patch

from app import llm
from app.db import Database
from app.pipeline import Pipeline, load_demo_records
from app.qa import AnswerEngine


def _portfolio_fixture(
    number: int, product: str, *, day: int = 20,
    severity: str = "HIGH", cvss: float = 8.1,
) -> dict:
    """Synthetic advisory with the affected product distinct from body mentions."""
    canonical = f"CVE-2026-{number}"
    return {
        "external_id": f"{canonical}::{product}",
        "title": f"{canonical}: {product} AI security advisory",
        "summary": (
            f"{product} is an AI inference framework with a request validation flaw."
            if product in {"vllm", "lmdeploy", "llama-cpp-python"} else
            f"{product} is an AI application which mentions vLLM in its deployment guide."
        ),
        "body": f"Security advisory for affected product {product}.",
        "url": f"https://example.invalid/advisory/{canonical.lower()}",
        "published_at": f"2026-09-{day:02d}T12:00:00Z",
        "source_id": "nvd_fixture",
        "source_category": "nvd",
        "kind": "vulnerability",
        "product": product,
        "identifiers": [canonical],
        "cvss": cvss,
        "severity": severity,
        "versions": ["<2.0.0"],
        "fixed_versions": [],
        "refs": [],
        "raw": {"snapshot_type": "unit_test_fixture"},
    }


class QAQualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "qa.sqlite3")
        self.pipeline = Pipeline(self.db, sources=[])
        self.pipeline.run_demo()
        self.qa = AnswerEngine(self.db)

    def tearDown(self):
        self.temp.cleanup()

    def _portfolio_db(self, records: list[dict], assets: list[dict] | None = None) -> Database:
        db = Database(Path(self.temp.name) / "portfolio.sqlite3")
        Pipeline(db, sources=[]).run_demo(records=records, assets=assets or [])
        return db

    def test_product_repair_question_contains_the_repair_evidence(self):
        answer = self.qa.ask("Ollama 的修复版本是什么？")
        self.assertFalse(answer["abstained"])
        self.assertIn("0.1.34", answer["answer"])
        self.assertIn("[1]", answer["answer"])

    def test_recent_vulnerability_repairs_with_sources_uses_vulnerability_evidence(self):
        records = [
            {**_portfolio_fixture(89001, "vllm", day=20, cvss=9.8),
             "fixed_versions": ["2.0.1"]},
            {**_portfolio_fixture(89002, "langflow", day=28, cvss=5.3),
             "severity": "MEDIUM", "fixed_versions": ["2.1.0"]},
            _portfolio_fixture(89003, "ollama", day=27, cvss=7.1),
        ]
        db = self._portfolio_db(records)
        answer = AnswerEngine(db, allow_model=False).ask(
            "请给出最近漏洞的修复建议，并列出证据来源。")
        self.assertFalse(answer["abstained"])
        self.assertTrue(answer["citations"])
        self.assertEqual(answer["citations"][0]["published_at"][:10], "2026-09-28")
        self.assertIn("CVE-2026-89002", answer["answer"])
        self.assertIn("2.1.0", answer["answer"])
        self.assertIn("核对厂商公告", answer["answer"])
        self.assertIn("不保证实时", answer["answer"])
        self.assertIn("[1]", answer["answer"])
        self.assertTrue(all(citation["url"].startswith("https://example.invalid/")
                            for citation in answer["citations"]))

    def test_specific_paper_request_still_uses_knowledge_route(self):
        answer = AnswerEngine(self.db, allow_model=False).ask(
            "AgentDojo 相关的提示词注入论文有哪些？")
        self.assertFalse(answer["abstained"])
        self.assertIn("arxiv", {c["source_id"] for c in answer["citations"]})

    def test_recent_portfolio_does_not_wait_for_unneeded_model_synthesis(self):
        db = self._portfolio_db([_portfolio_fixture(89004, "vllm", day=28)])
        with patch.object(llm, "enabled", return_value=True), \
             patch.object(llm, "plan", return_value={"answer_mode": "retrieval", "intents": ["fix"],
                                                       "search_terms": []}), \
             patch.object(llm, "synthesize_evidence") as synthesize:
            answer = AnswerEngine(db).ask("请给出最近漏洞的修复建议，并列出证据来源。")
        self.assertFalse(answer["abstained"])
        self.assertIn("planning", answer["model_role"])
        synthesize.assert_not_called()

    def test_specific_unsupported_knowledge_does_not_fall_back_to_category(self):
        for question in ("欧盟 AI 政策的罚款金额是多少？", "中国人工智能模型水印标准有哪些？"):
            with self.subTest(question=question):
                answer = self.qa.ask(question)
                self.assertTrue(answer["abstained"])
                self.assertEqual(answer["citations"], [])
        broad = self.qa.ask("AI 安全领域有哪些政策法规？")
        self.assertFalse(broad["abstained"])
        self.assertIn("生成式人工智能", broad["answer"])

    def test_unknown_kev_status_is_not_reported_as_negative(self):
        answer = self.qa.ask("CVE-2024-37032 是否在 CISA KEV？")
        self.assertTrue(answer["abstained"])
        self.assertIn("不能确认", answer["answer"])
        self.assertNotIn("未被收录", answer["answer"])

    def test_questions_are_not_logged_in_plaintext(self):
        secret = "Private-Token-qa-audit-7941"
        self.qa.ask(f"{secret} 对应什么漏洞？")
        events = "\n".join(str(event["detail"]) for event in self.db.recent_events(20))
        self.assertNotIn(secret, events)
        self.assertIn("question_sha256_prefix=", events)

    def test_newly_ingested_product_and_versions_are_kept_separate(self):
        extra = {
            "external_id": "mlflow-advisory-2024-37032",
            "title": "CVE-2024-37032 mlflow 测试公告",
            "summary": "仅用于验证同一 CVE 多产品范围不会串用。",
            "body": "mlflow 1.x 受影响，2.0.0 已修复。",
            "url": "https://example.invalid/mlflow-advisory",
            "published_at": "2024-07-01",
            "source_id": "mlflow_test",
            "source_category": "vendor",
            "kind": "vulnerability",
            "product": "mlflow",
            "identifiers": ["CVE-2024-37032"],
            "versions": ["< 2.0.0"],
            "fixed_versions": ["2.0.0"],
            "refs": [],
            "raw": {"snapshot_type": "unit_test_fixture"},
        }
        self.pipeline.run_demo(records=load_demo_records() + [extra])
        answer = self.qa.ask("CVE-2024-37032 mlflow 的修复版本是什么？")
        self.assertFalse(answer["abstained"])
        self.assertIn("2.0.0", answer["answer"])
        self.assertNotIn("修复版本证据：0.1.34", answer["answer"])
        product_answer = self.qa.ask("mlflow 的修复版本是什么？")
        self.assertIn("2.0.0", product_answer["answer"])

    def test_inference_framework_portfolio_filters_and_explains_coverage(self):
        # More than eight relevant findings test whether a recency-only top-8
        # silently hides whole product families. Decoys mention vLLM in prose,
        # but their affected products are an MCP server and an AI agent.
        records = [
            *(_portfolio_fixture(80100 + i, "vllm", day=20 + i) for i in range(9)),
            _portfolio_fixture(80201, "lmdeploy", day=10),
            _portfolio_fixture(80202, "llama-cpp-python", day=9),
            _portfolio_fixture(80301, "dbhub", day=29, cvss=9.3),
            _portfolio_fixture(80302, "decepticon", day=29, cvss=10.0),
            _portfolio_fixture(80303, "vllm", day=29, severity="LOW", cvss=3.1),
        ]
        db = self._portfolio_db(records)
        answer = AnswerEngine(db, allow_model=False).ask(
            "目前有哪些与 AI 推理框架相关的高危漏洞？"
        )
        text = answer["answer"]
        self.assertFalse(answer["abstained"])
        for product in ("vllm", "lmdeploy", "llama-cpp-python"):
            self.assertIn(product, text)
        cited_products = {db.document_group(cve)[0]["product"] for cve in
                          set(re.findall(r"CVE-2026-80\d{3}", " ".join(c["title"] for c in answer["citations"])))}
        self.assertEqual(cited_products, {"vllm", "lmdeploy", "llama-cpp-python"})
        self.assertNotIn("CVE-2026-80301", text)
        self.assertNotIn("CVE-2026-80302", text)
        self.assertNotIn("CVE-2026-80303", text)
        self.assertNotIn("资产", text, "没有询问资产时不应混入资产结论")
        self.assertRegex(text, r"(?:本地|知识库)")
        self.assertRegex(text, r"(?:共|总计|检索到|匹配)\s*11\s*(?:个|条)")
        shown = set(re.findall(r"CVE-2026-80\d{3}", text))
        if len(shown) < 11:
            self.assertRegex(text, r"(?:代表|部分|仅列|仅展示|展示|前\s*\d+)")

    def test_product_high_query_filters_medium_and_preserves_source_citations(self):
        db = self._portfolio_db([
            _portfolio_fixture(83001, "vllm", cvss=8.1),
            _portfolio_fixture(83002, "vllm", severity="MEDIUM", cvss=5.3),
        ])
        answer = AnswerEngine(db, allow_model=False).ask("vLLM 有哪些高危漏洞？")
        self.assertIn("CVE-2026-83001", answer["answer"])
        self.assertNotIn("CVE-2026-83002", answer["answer"])
        self.assertEqual(len(answer["citations"]), 1)
        self.assertIn("并非实时全网", answer["answer"])

    def test_model_asset_false_positive_does_not_change_question_scope(self):
        records = [_portfolio_fixture(80401, "vllm", day=20)]
        asset_name = "演示-虚构-推理节点"
        db = self._portfolio_db(records, [{
            "name": asset_name, "product": "vllm", "version": "1.0.0",
            "exposure": "internet", "criticality": 5, "demo_only": True,
        }])
        with patch.object(llm, "enabled", return_value=True), \
                patch.object(llm, "plan", return_value={
                    "intents": ["risk", "asset"], "search_terms": ["推理框架"],
                }), \
                patch.object(llm, "select_evidence", return_value=list(range(20))), \
                patch.object(llm, "status", return_value={
                    "configured": True, "model": "glm-5.3", "provider": "Zhipu AI",
                }):
            answer = AnswerEngine(db).ask(
                "目前有哪些与 AI 推理框架相关的高危漏洞？"
            )
        self.assertFalse(answer["abstained"])
        self.assertTrue(answer["model_used"])
        self.assertIn("CVE-2026-80401", answer["answer"])
        self.assertNotIn(asset_name, answer["answer"])
        self.assertNotIn("潜在受影响", answer["answer"])

    def test_inference_framework_query_reaches_beyond_newest_200_records(self):
        # The old implementation requests only the latest 200 vulnerability
        # documents before applying topic filters; the target must remain
        # discoverable when a broad feed has a larger unrelated backlog.
        records = [
            *(_portfolio_fixture(81000 + i, "dbhub", day=20) for i in range(205)),
            _portfolio_fixture(82001, "vllm", day=1),
        ]
        db = self._portfolio_db(records)
        answer = AnswerEngine(db, allow_model=False).ask(
            "目前有哪些与 AI 推理框架相关的高危漏洞？"
        )
        self.assertFalse(answer["abstained"])
        self.assertIn("CVE-2026-82001", answer["answer"])
        self.assertNotIn("CVE-2026-81000", answer["answer"])


    def test_portfolio_without_risk_intent_still_routes_by_topic(self):
        records = [_portfolio_fixture(80501, "vllm"), _portfolio_fixture(80502, "dbhub")]
        db = self._portfolio_db(records)
        answer = AnswerEngine(db, allow_model=False).ask("AI 推理框架的漏洞有哪些？")
        self.assertFalse(answer["abstained"])
        self.assertIn("CVE-2026-80501", answer["answer"])
        self.assertNotIn("CVE-2026-80502", answer["answer"])

    def test_portfolio_assets_are_aggregated_not_repeated_per_item(self):
        records = [_portfolio_fixture(80601, "vllm"), _portfolio_fixture(80602, "lmdeploy")]
        db = self._portfolio_db(records, [
            {"name": "演示-虚构-推理节点A", "product": "vllm", "version": "1.0.0",
             "exposure": "internet", "criticality": 5},
        ])
        answer = AnswerEngine(db, allow_model=False).ask(
            "AI 推理框架的高危漏洞影响哪些登记资产？")
        text = answer["answer"]
        self.assertIn("演示-虚构-推理节点A", text)
        self.assertIn("登记资产聚合", text)
        self.assertNotIn("未发现", text, "未命中资产应聚合说明，而不是逐条重复")
        self.assertEqual(text.count("登记资产聚合"), 1)
        self.assertTrue(any(step["via"] == "local_asset_version_match"
                            for step in answer["trace"]))

    def test_portfolio_fix_dimension_reports_readiness(self):
        records = [
            _portfolio_fixture(80701, "vllm"),
            {**_portfolio_fixture(80702, "lmdeploy"), "fixed_versions": ["1.0.2"]},
        ]
        db = self._portfolio_db(records)
        answer = AnswerEngine(db, allow_model=False).ask(
            "AI 推理框架的高危漏洞有哪些修复建议？")
        self.assertIn("修复就绪度", answer["answer"])
        self.assertIn("1.0.2", answer["answer"])

    def test_portfolio_ranks_with_model_and_falls_back_locally(self):
        records = [_portfolio_fixture(80800 + i, "vllm") for i in range(9)]
        db = self._portfolio_db(records)
        with patch.object(llm, "enabled", return_value=True), \
                patch.object(llm, "plan", return_value={"intents": ["risk"], "search_terms": []}), \
                patch.object(llm, "rank_vulnerabilities",
                             side_effect=RuntimeError("模型尚未配置")) as rank, \
                patch.object(llm, "status", return_value={
                    "configured": True, "model": "glm-5.3", "provider": "Zhipu AI"}):
            answer = AnswerEngine(db).ask("AI 推理框架有哪些高危漏洞？")
        rank.assert_called_once()
        self.assertFalse(answer["abstained"])
        self.assertEqual(answer["model_role"], "planning",
                         "排序失败回退后不应声称模型排序参与")
        self.assertLessEqual(len(answer["citations"]), 8, "本地回退也应遵守展示上限")

    def test_portfolio_model_ranking_marks_role_and_skips_selection(self):
        records = [_portfolio_fixture(80900 + i, "vllm") for i in range(9)]
        db = self._portfolio_db(records)
        def fake_rank(question, candidates, max_items=8):
            return [candidate["id"] for candidate in candidates[:3]]
        with patch.object(llm, "enabled", return_value=True), \
                patch.object(llm, "plan", return_value={"intents": ["risk"], "search_terms": []}), \
                patch.object(llm, "rank_vulnerabilities", side_effect=fake_rank), \
                patch.object(llm, "select_evidence", return_value=list(range(20))) as select, \
                patch.object(llm, "status", return_value={
                    "configured": True, "model": "glm-5.3", "provider": "Zhipu AI"}):
            answer = AnswerEngine(db).ask("AI 推理框架有哪些高危漏洞？")
        select.assert_not_called()
        self.assertEqual(answer["model_role"], "planning+evidence_ranking")
        self.assertEqual(len(answer["citations"]), 8)


if __name__ == "__main__":
    unittest.main()
