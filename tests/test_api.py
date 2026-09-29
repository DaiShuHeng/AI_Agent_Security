"""Real localhost HTTP integration, isolated database, no cloud or feed traffic."""
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from app.db import Database
from app.pipeline import Pipeline
from app.qa import AnswerEngine
from app.server import make_handler


class APITests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Database(Path(temp.name) / 'api.sqlite3')
        self.pipeline = Pipeline(self.db, sources=[])
        self.pipeline.run_demo()
        self.qa = AnswerEngine(self.db, allow_model=False)
        no_network = patch('app.connectors.fetch_source', side_effect=AssertionError('feed network forbidden'))
        no_network.start()
        self.addCleanup(no_network.stop)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.db, self.pipeline, self.qa))
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval':0.01})
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive(), 'server thread leaked')

    def request(self, path, payload=None, *, method=None, body=None, headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            if payload is not None:
                body = json.dumps(payload).encode()
                headers = {'Content-Type':'application/json', **(headers or {})}
            connection.request(method or ('POST' if body is not None else 'GET'), path, body=body, headers=headers or {})
            response = connection.getresponse()
            raw = response.read()
            content_type = response.getheader('Content-Type', '')
            data = json.loads(raw) if 'application/json' in content_type else raw.decode()
            return response.status, content_type, data
        finally:
            connection.close()

    def test_server_smoke_and_read_endpoints(self):
        for path in ('/', '/index.html', '/api/health', '/api/dashboard', '/api/documents',
                     '/api/vulnerabilities', '/api/sources', '/api/runs', '/api/assets', '/api/security-selfcheck'):
            with self.subTest(path=path):
                status, content_type, data = self.request(path)
                self.assertEqual(status, 200)
                self.assertTrue(data)
        self.assertEqual(self.request('/api/health')[2]['status'], 'ok')

    def test_vulnerability_details_and_missing_entity(self):
        status, _, data = self.request('/api/vulnerabilities/CVE-2024-37032')
        self.assertEqual(status, 200)
        self.assertTrue(data['documents'])
        self.assertTrue(data['claims'])
        self.assertEqual(self.request('/api/vulnerabilities/CVE-2099-99999')[0], 404)

    def test_question_evidence_abstention_and_paper_route(self):
        for question, abstained in (('CVE-2024-37032 的修复版本是什么？', False),
                                   ('CVE-2099-99999 的修复版本是什么？', True),
                                   ('AgentDojo 相关的提示词注入论文是什么？', False)):
            with self.subTest(question=question):
                status, _, data = self.request('/api/ask', {'question':question})
                self.assertEqual(status, 200)
                self.assertEqual(data['abstained'], abstained)
                self.assertEqual(bool(data['citations']), not abstained)
        self.assertEqual(self.request('/api/ask', {'question':''})[0], 400)

    def test_invalid_request_bodies(self):
        for body, headers in ((b'{}', {}), (b'{bad json', {'Content-Type':'application/json'}),
                              (b'[]', {'Content-Type':'application/json'}),
                              (b'{}', {'Content-Type':'application/json', 'Content-Length':'1000001'})):
            with self.subTest(body=body, headers=headers):
                self.assertEqual(self.request('/api/ask', body=body, headers=headers)[0], 400)

    def test_cross_origin_and_path_traversal(self):
        self.assertEqual(self.request('/api/assets', {'name':'evil'}, headers={'Origin':'http://evil.example'})[0], 400)
        for path in ('/../../etc/passwd', '/%2e%2e/%2e%2e/etc/passwd', '/%2e%2e/app/server.py', '/.env.local'):
            self.assertEqual(self.request(path)[0], 404, path)

    def test_assets_reject_missing_or_invalid_fields_without_inserting(self):
        valid = {'name':'test','product':'ollama','version':'0.1.33'}
        invalid = [{'name':'test'}, {}, *({**valid, key:value} for key, value in (
            ('name', None), ('product', []), ('version', {}), ('version', ' '),
            ('criticality', 0), ('criticality', 6), ('criticality', True),
            ('criticality', 2.5), ('criticality', None), ('exposure', 'public'),
            ('exposure', None), ('owner', ['private'])))]
        before = self.db.assets()
        for payload in invalid:
            with self.subTest(payload=payload):
                self.assertEqual(self.request('/api/assets', payload)[0], 400)
        self.assertEqual(before, self.db.assets())

    def test_assets_create_and_update(self):
        payload = {'name':'test','product':'Ollama','version':'0.1.33','owner':'team','criticality':5,'exposure':'internal'}
        status, _, created = self.request('/api/assets', payload)
        self.assertEqual(status, 201)
        status, _, updated = self.request('/api/assets', {**payload,'version':'0.1.34'})
        self.assertEqual(status, 201)
        self.assertEqual(created['id'], updated['id'])
        self.assertEqual(updated['item']['version'], '0.1.34')

    def test_metrics_no_fabricated_latency(self):
        status, content_type, text = self.request('/metrics')
        self.assertEqual(status, 200)
        self.assertTrue(content_type.startswith('text/plain'))
        for name in ('zhidun_documents', 'zhidun_vulnerabilities', 'zhidun_claims', 'zhidun_sources_healthy'):
            self.assertIn(name, text)
        self.assertNotIn('NaN', text)
        self.assertNotIn('scope="live",stat="p50_hours"', text)

    def test_live_admission_is_atomic_and_run_can_be_followed(self):
        self.pipeline.sources = [{'id':'fixture','name':'Fixture','type':'rss','category':'paper','url':'https://example.invalid/feed','enabled':True}]
        self.db.configure_sources(self.pipeline.sources)
        entered, release = threading.Event(), threading.Event()
        def fetch(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise AssertionError('worker did not get released')
            return []
        with patch('app.connectors.fetch_source', side_effect=fetch):
            try:
                status, _, accepted = self.request('/api/collect', {'mode':'live'})
                self.assertEqual(status, 202)
                self.assertTrue(entered.wait(2))
                run_id = accepted['run_id']
                before = len(self.db.recent_runs(30))
                self.assertEqual(self.request('/api/collect', {'mode':'live'})[0], 409)
                self.assertEqual(self.request('/api/collect', {'mode':'demo'})[0], 409)
                self.assertEqual(len(self.db.recent_runs(30)), before)
                self.assertEqual(self.request(f'/api/runs/{run_id}')[2]['run']['status'], 'running')
            finally:
                release.set()
                worker = next((t for t in threading.enumerate() if t.name == f'collect-{accepted["run_id"]}'), None)
                if worker:
                    worker.join(5)
                    self.assertFalse(worker.is_alive())
            self.assertEqual(self.request(f'/api/runs/{run_id}')[2]['run']['status'], 'success')
        for identifier in ('999999', 'invalid', '-1'):
            self.assertEqual(self.request(f'/api/runs/{identifier}')[0], 404)
        self.assertEqual(self.request('/api/collect', {'mode':'live','source_id':'missing'})[0], 400)

    def test_worker_start_failure_releases_reservation(self):
        with patch('app.pipeline.threading.Thread.start', side_effect=RuntimeError('cannot start')):
            with self.assertRaises(RuntimeError):
                self.pipeline.start_live()
        self.assertEqual(self.db.recent_runs(1)[0]['status'], 'failed')
        self.assertEqual(self.pipeline.run_live()['status'], 'success')

    def test_source_failure_is_partial_and_other_sources_continue(self):
        sources = [{'id':key,'name':key,'type':'rss','category':'paper','url':'https://example.invalid/feed','enabled':True} for key in ('blocked','healthy')]
        pipeline = Pipeline(self.db, sources=sources)
        def fetch(source, **kwargs):
            if source['id'] == 'blocked':
                raise PermissionError('HTTP 403')
            return []
        with patch('app.connectors.fetch_source', side_effect=fetch) as mock_fetch, patch('app.pipeline.time.sleep'):
            result = pipeline.run_live()
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['errors'], 1)
        self.assertEqual(mock_fetch.call_count, 4)
        rows = {row['id']:row for row in self.db.source_rows()}
        self.assertIn('403', rows['blocked']['last_error'])
        self.assertEqual(rows['blocked']['status'], 'error')
        self.assertEqual(rows['healthy']['status'], 'healthy')
