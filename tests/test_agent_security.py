"""Agentic AI 自安全测试：注入隔离、会话隔离、工具边界、最小权限、拒答与审计。

对应 app/security_selfcheck.py，可在 CI 中回归；OWASP 攻击面映射是项目自定口径。
"""

from __future__ import annotations

import unittest

from app.pipeline import load_demo_records
from app.qa import AnswerEngine
from app.security_selfcheck import INJECTION_RECORD, run_selfcheck


class AgentSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_selfcheck()
        cls.by_id = {item["id"]: item for item in cls.report["checks"]}

    def test_all_selfchecks_pass(self):
        failed = [item["id"] for item in self.report["checks"] if not item["passed"]]
        self.assertEqual(failed, [], f"自检未通过项：{failed}")

    def test_injection_payload_is_data_not_instruction(self):
        """注入载荷必须只作为可检索数据存在，问答不得出现服从性表述。"""
        check = self.by_id["reasoning_injection_isolation"]
        self.assertTrue(check["passed"], check["evidence"])
        self.assertIn("作为普通数据入库=True", check["evidence"])
        self.assertIn("无服从性表述=True", check["evidence"])

    def test_session_context_does_not_leak_across_sessions(self):
        check = self.by_id["memory_session_isolation"]
        self.assertTrue(check["passed"], check["evidence"])

    def test_reference_claims_are_https_only(self):
        """对抗样例的 file:// 与本机 http 链接必须被拒收。"""
        check = self.by_id["tools_reference_protocol_whitelist"]
        self.assertTrue(check["passed"], check["evidence"])
        # INJECTION_RECORD.refs 携带三条链接，仅 https 一条应被收录
        self.assertEqual([r for r in INJECTION_RECORD["refs"] if r.startswith("https://")],
                         ["https://example.invalid/poc.py"])

    def test_planner_stays_local_without_llm_env(self):
        check = self.by_id["identity_least_privilege"]
        self.assertTrue(check["passed"], check["evidence"])

    def test_unknown_entity_must_abstain_without_citations(self):
        check = self.by_id["oversight_abstention"]
        self.assertTrue(check["passed"], check["evidence"])

    def test_agent_events_and_idempotent_replay(self):
        check = self.by_id["multi_agent_audit_trail"]
        self.assertTrue(check["passed"], check["evidence"])

    def test_adversarial_fixture_never_poisons_canonical_entities(self):
        """对抗文档提及 CVE-2024-34359 只能产生 mentioned_in 边，不得冒充该 CVE 公告。"""
        from tempfile import TemporaryDirectory
        from pathlib import Path
        from app.db import Database
        from app.pipeline import Pipeline

        with TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "t.sqlite3")
            pipeline = Pipeline(db, sources=[])
            pipeline.run_demo(records=load_demo_records() + [INJECTION_RECORD])
            group = db.document_group("CVE-2024-34359")
            sources = {doc["source_id"] for doc in group}
            self.assertNotIn("adversarial_test", sources,
                             "对抗文档被误并入 CVE 证据组")
            related = db.related_documents("CVE-2024-34359")
            self.assertIn("adv-injection-2026",
                          [doc["external_id"] for doc in related],
                          "mentioned_in 关联应能检索到对抗文档")
            qa = AnswerEngine(db)
            answer = qa.ask("CVE-2024-34359 相关研究论文有哪些？")
            self.assertFalse(answer["abstained"])
            self.assertTrue(any(c["source_id"] == "adversarial_test" for c in answer["citations"]))


if __name__ == "__main__":
    unittest.main()
