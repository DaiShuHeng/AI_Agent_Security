"""GLM transport and answer-boundary tests without making paid API calls."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import llm
from app.db import Database
from app.pipeline import Pipeline
from app.qa import AnswerEngine


class GLMTests(unittest.TestCase):
    def test_official_endpoint_payload_and_key_is_header_only(self):
        response = io.BytesIO(json.dumps({
            "choices": [{"message": {"content": '{"intents":["fix"],"search_terms":["Ollama"]}'}}
                       ]}).encode())
        captured = {}

        def fake_open(request, timeout, context):
            captured["request"] = request
            captured["timeout"] = timeout
            captured["context"] = context
            return response

        with patch.dict(os.environ, {"ZHIPU_API_KEY": "test-id.test-secret",
                                     "ZHIPU_BASE_URL": llm.DEFAULT_ZHIPU_BASE,
                                     "ZHIPU_MODEL": "glm-5.3"}), patch.object(llm, "urlopen", fake_open):
            result = llm.plan("Ollama 如何修复？")
        self.assertEqual(result["intents"], ["fix"])
        request = captured["request"]
        self.assertEqual(request.full_url,
                         "https://open.bigmodel.cn/api/paas/v4/chat/completions")
        body = json.loads(request.data)
        self.assertEqual(body["model"], "glm-5.3")
        self.assertEqual(body["thinking"], {"type": "enabled"})
        self.assertEqual(body["reasoning_effort"], "low")
        self.assertNotIn("test-secret", json.dumps(body))
        self.assertEqual(request.get_header("Authorization"), "Bearer test-id.test-secret")

    def test_local_secret_file_requires_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret = Path(tmp) / ".env.local"
            secret.write_text("ZHIPU_API_KEY=test-id.test-secret\n", encoding="utf-8")
            secret.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "chmod 600"):
                llm.load_local_config(secret)

    def test_selection_cannot_write_new_security_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "qa.sqlite3")
            Pipeline(db, sources=[]).run_demo()
            qa = AnswerEngine(db)
            with patch.object(llm, "enabled", return_value=True), \
                    patch.object(llm, "plan", return_value={"intents": ["fix"], "search_terms": []}), \
                    patch.object(llm, "select_evidence", return_value=[0, 1, 2, 3]), \
                    patch.object(llm, "status", return_value={"configured": True,
                                                              "model": "glm-5.3", "provider": "Zhipu AI"}):
                answer = qa.ask("CVE-2024-37032 如何修复？")
            self.assertTrue(answer["model_used"])
            self.assertEqual(answer["model_role"], "planning+evidence_selection")
            self.assertIn("0.1.34", answer["answer"])
            self.assertNotIn("test-secret", answer["answer"])

    def test_network_failure_returns_grounded_local_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "qa.sqlite3")
            Pipeline(db, sources=[]).run_demo()
            qa = AnswerEngine(db)
            with patch.object(llm, "enabled", return_value=True), \
                    patch.object(llm, "plan", side_effect=TimeoutError("private transport detail")), \
                    patch.object(llm, "status", return_value={"configured": True,
                                                              "model": "glm-5.3", "provider": "Zhipu AI"}):
                answer = qa.ask("CVE-2024-37032 如何修复？")
            self.assertFalse(answer["model_used"])
            self.assertEqual(answer["model_role"], "local")
            self.assertEqual(answer["model_fallback_reason"], "TimeoutError")
            self.assertIn("0.1.34", answer["answer"])
            self.assertNotIn("private transport detail", json.dumps(answer, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
