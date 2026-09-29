"""Concept usability and evidence-generation boundaries, using mocked model output."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import llm
from app.concepts import concept_question
from app.db import Database
from app.pipeline import Pipeline
from app.qa import AnswerEngine


class AnswerModeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / 'qa.sqlite3')
        Pipeline(self.db, sources=[]).run_demo()
        self.qa = AnswerEngine(self.db)

    def tearDown(self):
        self.temp.cleanup()

    def test_evidence_requests_are_not_hijacked_even_with_concept_history(self):
        for question in ('AgentDojo 相关的提示词注入论文是什么？',
                         '有哪些关于提示词注入的论文？', 'ISO/IEC 42001 是什么标准？',
                         '有哪些 AI 安全政策？', '这篇安全报告是什么？', '某厂商公告是什么？'):
            with self.subTest(question=question):
                self.assertFalse(concept_question(question, True, 'concept'))
        qa = AnswerEngine(self.db, allow_model=False)
        answer = qa.ask('AgentDojo 相关的提示词注入论文是什么？')
        self.assertFalse(answer['abstained'])
        self.assertIn('AgentDojo', answer['answer'])
        self.assertIn('arxiv', {c['source_id'] for c in answer['citations']})
        with patch.object(llm, 'enabled', return_value=True), \
             patch.object(llm, 'plan', return_value={'answer_mode':'concept','intents':[], 'search_terms':[]}), \
             patch.object(llm, 'explain_concept') as explain, \
             patch.object(llm, 'synthesize_evidence', return_value='基于论文的解释 [1]'):
            online = self.qa.ask('AgentDojo 相关的提示词注入论文是什么？')
        explain.assert_not_called()
        self.assertFalse(online['abstained'])
        self.assertIn('arxiv', {c['source_id'] for c in online['citations']})

    def test_definitions_still_use_concept_route(self):
        for question in ('提示词注入是什么？', 'AI 安全是什么？', 'CVSS 是什么意思？',
                         'RAG 有什么安全风险？', 'vLLM 是什么？'):
            self.assertTrue(concept_question(question), question)

    def test_screenshot_question_uses_model_explanation_without_retrieval_refusal(self):
        with patch.object(llm, 'enabled', return_value=True), \
             patch.object(llm, 'explain_concept', return_value='AI 安全涵盖模型、数据、应用和运行环境的风险。') as explain, \
             patch.object(llm, 'plan') as plan:
            answer = self.qa.ask('ai安全是什么')
        self.assertFalse(answer['abstained'])
        self.assertEqual(answer['answer_basis'], 'general_knowledge')
        self.assertEqual(answer['model_role'], 'concept_explanation')
        self.assertEqual(answer['citations'], [])
        plan.assert_not_called()
        explain.assert_called_once()

    def test_concept_followup_receives_only_concept_history(self):
        with patch.object(llm, 'enabled', return_value=True), \
             patch.object(llm, 'explain_concept', return_value='提示词注入将外部数据伪装成指令。') as explain:
            first = self.qa.ask('提示词注入是什么？')
            self.qa.ask('举个例子，并说说怎么防范', first['session_id'])
        history = explain.call_args.args[1]
        self.assertEqual(history[0]['content'], '提示词注入是什么？')
        self.assertNotIn('资产', str(history))

    def test_concept_routing_does_not_bypass_concrete_evidence(self):
        for question in ('目前有哪些 AI 安全漏洞？', 'CVE-2099-99999 是什么？',
                         '我们部署的 AI 是否安全？', 'AI 法规罚款是多少？',
                         '解释 vLLM 0.29.0 的漏洞', '最新提示词注入事件有哪些？'):
            self.assertFalse(concept_question(question, True, 'concept'), question)
        with patch.object(llm, 'enabled', return_value=True), \
             patch.object(llm, 'plan', return_value={'answer_mode':'concept','intents':[], 'search_terms':[]}), \
             patch.object(llm, 'explain_concept') as explain:
            answer = self.qa.ask('CVE-2099-99999 是什么？')
        self.assertTrue(answer['abstained'])
        explain.assert_not_called()

    def test_ai_security_has_honest_offline_fallback(self):
        with patch.object(llm, 'enabled', return_value=True), \
             patch.object(llm, 'explain_concept', side_effect=TimeoutError('do not disclose')):
            answer = self.qa.ask('什么是AI安全？')
        self.assertFalse(answer['abstained'])
        self.assertFalse(answer['model_used'])
        self.assertEqual(answer['model_fallback_reason'], 'TimeoutError')
        self.assertNotIn('do not disclose', str(answer))

    def test_concept_response_rejects_fabricated_citation(self):
        with patch.object(llm, '_request', return_value={'answer':'新漏洞 CVE-2099-99999 已被验证。[1]'}):
            with self.assertRaises(ValueError):
                llm.explain_concept('AI安全是什么？')

    def test_valid_synthesis_keeps_anchors_and_marks_authorship(self):
        with patch.object(llm, 'enabled', return_value=True), \
             patch.object(llm, 'plan', return_value={'intents':['risk'], 'search_terms':[]}), \
             patch.object(llm, 'synthesize_evidence', return_value='该问题源于模型路径校验不足。[1]') as synth:
            answer = self.qa.ask('CVE-2024-37032 的风险原理是什么？')
        self.assertIn('evidence_synthesis', answer['model_role'])
        self.assertIn('结构化证据核对', answer['answer'])
        self.assertIn('body:', synth.call_args.args[1][0]['text'])
        self.assertNotIn('演示-虚构', str(synth.call_args.args[1]))

    def test_synthesis_validator_checks_quote_reference_and_numbers(self):
        cards = [{'id':1,'text':'CVE-2024-37032 模型路径未充分校验，fixed_versions: 0.1.34。'}]
        paragraph = {'text':'CVE-2024-37032 的修复版本为 0.1.34。',
                     'evidence':[{'id':1,'quote':'模型路径未充分校验'}]}
        with patch.object(llm, '_request', return_value={'paragraphs':[paragraph]}):
            self.assertIn('[1]', llm.synthesize_evidence('如何修复？', cards))
        bad = [dict(paragraph, text='CVE-2024-37032 已于 0.9.99 修复。'),
               dict(paragraph, text='修复版本为 0.1.3。'),
               dict(paragraph, evidence=[{'id':99,'quote':'模型路径未充分校验'}]),
               dict(paragraph, evidence=[{'id':1,'quote':'这个完全不存在的原文'}])]
        for item in bad:
            with patch.object(llm, '_request', return_value={'paragraphs':[item]}):
                with self.assertRaises(ValueError):
                    llm.synthesize_evidence('如何修复？', cards)

    def test_synthesis_cannot_misattribute_products_or_recommend_unconfirmed_patch(self):
        cards = [{'id':1,'text':'product: ollama\nfixed_versions: []\n正文称 0.9.9 已修复，等待核验。'},
                 {'id':2,'text':'product: vllm\nfixed_versions: []\n接口 /v1/embeddings 可能受到影响。'}]
        for text in ('vLLM 的部署需核验。', '建议升级至 0.9.9。', '建议限制 /tokenize 访问。'):
            paragraph = {'text':text,'evidence':[{'id':1,'quote':'正文称 0.9.9 已修复'}]}
            with patch.object(llm, '_request', return_value={'paragraphs':[paragraph]}):
                with self.assertRaises(ValueError):
                    llm.synthesize_evidence('如何处置？',cards)

    def test_synthesis_repairs_invalid_anchor_once(self):
        cards = [{'id':1,'text':'公告确认该产品存在模型路径校验不足。'}]
        bad = {'paragraphs':[{'text':'存在路径校验不足。','evidence':[{'id':8,'quote':'模型路径校验不足。'}]}]}
        good = {'paragraphs':[{'text':'存在路径校验不足。','evidence':[{'id':1,'quote':'该产品存在模型路径校验不足'}]}]}
        with patch.object(llm, '_request', side_effect=[bad,good]) as request:
            answer = llm.synthesize_evidence('为什么有风险？',cards)
        self.assertIn('[1]',answer)
        self.assertEqual(request.call_count,2)

    def test_asset_query_never_sends_asset_data_for_synthesis(self):
        with patch.object(llm, 'enabled', return_value=True), \
             patch.object(llm, 'plan', return_value={'intents':['asset'], 'search_terms':[]}), \
             patch.object(llm, 'synthesize_evidence') as synth, \
             patch.object(llm, 'select_evidence', return_value=[0,1]):
            answer = self.qa.ask('CVE-2024-37032 影响哪些登记资产？')
        synth.assert_not_called()
        self.assertIn('本地', answer['answer'])

    def test_synthesis_failure_keeps_grounded_answer(self):
        with patch.object(llm, 'enabled', return_value=True), \
             patch.object(llm, 'plan', return_value={'intents':['fix'], 'search_terms':[]}), \
             patch.object(llm, 'synthesize_evidence', side_effect=ValueError('unsupported source')), \
             patch.object(llm, 'select_evidence', return_value=[]):
            answer = self.qa.ask('CVE-2024-37032 如何修复？')
        self.assertFalse(answer['abstained'])
        self.assertIn('0.1.34', answer['answer'])
        self.assertNotIn('evidence_synthesis', answer['model_role'])
        self.assertEqual(answer['model_fallback_reason'], 'ValueError')
