"""Dependency-free HTTP API and static dashboard for local competition demos."""

from __future__ import annotations

import argparse
import json
import logging
import mimetypes
import os
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .db import Database
from .intelligence import asset_impacts, related_knowledge
from .pipeline import PROJECT_ROOT, Pipeline, Scheduler
from .qa import AnswerEngine
from . import llm

LOG = logging.getLogger(__name__)
WEB_ROOT = PROJECT_ROOT / "web"


def vulnerability_items(db: Database) -> list[dict]:
    rows: list[dict] = []
    offset = 0
    while True:
        batch = db.vulnerability_documents(limit=500, offset=offset)
        rows.extend(batch)
        if len(batch) < 500:
            break
        offset += len(batch)
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row["canonical_id"], []).append(row)
    cards = []
    for canonical, docs in groups.items():
        docs.sort(key=lambda doc: (doc["source_id"] != "nvd", -(doc["cvss"] or 0)))
        primary = docs[0]
        cards.append({
            "canonical_id": canonical, "title": primary["title"],
            "summary": primary["summary"], "product": primary["product"],
            "cvss": max((doc["cvss"] for doc in docs if doc["cvss"] is not None), default=None),
            "severity": primary["severity"], "published_at": primary["published_at"],
            "source_id": primary["source_id"], "source_count": len(docs),
            "asset_count": sum(impact["status"] == "affected" for impact in asset_impacts(db, canonical)),
        })
    return sorted(cards, key=lambda item: (item["asset_count"], item["cvss"] or 0), reverse=True)


def make_handler(db: Database, pipeline: Pipeline, qa: AnswerEngine):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Zhidun/0.1"

        def log_message(self, fmt, *args):
            LOG.info("%s %s", self.address_string(), fmt % args)

        def _headers(self, status: int, content_type: str, length: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()

        def _json(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def _error(self, status: int, message: str) -> None:
            self._json({"error": message}, status)

        def _payload(self) -> dict:
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError("Content-Type 必须为 application/json")
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc != self.headers.get("Host"):
                raise ValueError("禁止跨站写入本地情报服务")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ValueError("Content-Length 无效") from None
            if not 0 < length <= 1_000_000:
                raise ValueError("请求体不能为空或超过 1 MB")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("请求体必须为 JSON 对象")
            return data

        def do_GET(self):
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            params = parse_qs(parsed.query)
            try:
                if path == "/api/health":
                    self._json({"status": "ok", "database": str(db.path), "version": "0.1.0",
                                "model": llm.status()})
                elif path == "/api/dashboard":
                    self._json({"stats": db.stats(), "documents": db.documents(limit=8),
                                "sources": db.source_rows(), "runs": db.recent_runs(5),
                                "events": db.recent_events(12),
                                "latency": db.collection_latency_stats()})
                elif path == "/api/documents":
                    self._json({"items": db.documents(query=params.get("query", [""])[0],
                                                     kind=params.get("kind", [""])[0],
                                                     limit=int(params.get("limit", ["50"])[0]))})
                elif path == "/api/vulnerabilities":
                    self._json({"items": vulnerability_items(db)})
                elif path.startswith("/api/vulnerabilities/"):
                    canonical = path.rsplit("/", 1)[-1].upper()
                    documents = db.document_group(canonical)
                    if not documents:
                        self._error(404, "未找到该漏洞")
                    else:
                        products = list(dict.fromkeys(doc["product"] for doc in documents if doc["product"]))
                        related = related_knowledge(db, canonical, products)
                        related = [doc for doc in related if doc["id"] not in {d["id"] for d in documents}]
                        self._json({"documents": documents, "claims": db.claims(canonical),
                                    "assets": asset_impacts(db, canonical), "related": related})
                elif path == "/api/sources":
                    self._json({"items": db.source_rows()})
                elif path == "/api/security-selfcheck":
                    from .security_selfcheck import run_selfcheck
                    self._json(run_selfcheck())
                elif path == "/api/runs":
                    self._json({"items": db.recent_runs(30), "events": db.recent_events(80)})
                elif path == "/api/assets":
                    self._json({"items": db.assets()})
                elif path == "/metrics":
                    stats = db.stats()
                    latency = db.collection_latency_stats()
                    lines = [
                        "# HELP zhidun_documents Number of indexed source documents",
                        "# TYPE zhidun_documents gauge",
                        f"zhidun_documents {stats['documents']}",
                        f"zhidun_vulnerabilities {stats['vulnerabilities']}",
                        f"zhidun_claims {stats['claims']}",
                        f"zhidun_sources_healthy {stats['healthy_sources']}",
                        "# HELP zhidun_collect_latency_hours Publish-to-collection delay in hours",
                        "# TYPE zhidun_collect_latency_hours gauge",
                    ]
                    for scope in ("live", "demo_snapshot"):
                        bucket = latency[scope]
                        for name in ("samples", "p50_hours", "p95_hours", "max_hours"):
                            if bucket[name] is not None:
                                lines.append(f'zhidun_collect_latency_hours{{scope="{scope}",stat="{name}"}} {bucket[name]}')
                    data = ("\n".join(lines) + "\n").encode()
                    self._headers(200, "text/plain; version=0.0.4", len(data))
                    self.wfile.write(data)
                else:
                    self._static(path)
            except (ValueError, TypeError) as exc:
                self._error(400, str(exc))
            except Exception as exc:
                LOG.exception("GET %s failed", path)
                self._error(500, f"服务错误：{type(exc).__name__}")

        def _static(self, path: str) -> None:
            path = "/index.html" if path in {"/", ""} else path
            target = (WEB_ROOT / path.lstrip("/")).resolve()
            try:
                target.relative_to(WEB_ROOT.resolve())
            except ValueError:
                self._error(404, "文件不存在")
                return
            if not target.is_file():
                self._error(404, "文件不存在")
                return
            data = target.read_bytes()
            mime = mimetypes.guess_type(target)[0] or "application/octet-stream"
            self._headers(200, mime + ("; charset=utf-8" if mime.startswith("text/") or mime == "application/javascript" else ""), len(data))
            self.wfile.write(data)

        def do_POST(self):
            path = urlparse(self.path).path
            try:
                payload = self._payload()
                if path == "/api/ask":
                    self._json(qa.ask(str(payload.get("question", "")), payload.get("session_id")))
                elif path == "/api/assets":
                    asset_id = db.add_asset(payload)
                    self._json({"id": asset_id, "item": next(
                        (item for item in db.assets() if item["id"] == asset_id), None)}, 201)
                elif path == "/api/collect":
                    mode = payload.get("mode", "demo")
                    if mode == "demo":
                        self._json(pipeline.run_demo())
                    elif mode == "live":
                        source_id = payload.get("source_id")
                        if source_id and source_id not in {s["id"] for s in pipeline.sources}:
                            raise ValueError("未知数据源")
                        def run_background():
                            try:
                                pipeline.run_live(selected_source=source_id)
                            except Exception:
                                LOG.exception("Background live collection failed")
                        threading.Thread(target=run_background, daemon=True, name="manual-collect").start()
                        self._json({"status": "queued", "message": "在线采集已在后台启动，可在运行记录查看结果"}, 202)
                    else:
                        raise ValueError("mode 必须为 demo 或 live")
                else:
                    self._error(404, "API 不存在")
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._error(400, str(exc))
            except RuntimeError as exc:
                self._error(409, str(exc))
            except Exception as exc:
                LOG.exception("POST %s failed", path)
                self._error(500, f"服务错误：{type(exc).__name__}")

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="知盾 AI 安全知识情报系统")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default=str(PROJECT_ROOT / "data" / "zhidun.sqlite3"))
    parser.add_argument("--no-demo", action="store_true", help="不自动载入离线演示样例")
    parser.add_argument("--no-scheduler", action="store_true", help="关闭定时在线增量采集")
    parser.add_argument("--interval", type=int, default=int(os.getenv("COLLECT_INTERVAL_SECONDS", "1800")))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    llm.load_local_config(PROJECT_ROOT / ".env.local")
    LOG.info("Question model: %s", llm.status())
    db = Database(args.db)
    pipeline = Pipeline(db)
    if db.stats()["documents"] == 0 and not args.no_demo:
        LOG.info("Loading verified offline demonstration records")
        pipeline.run_demo()
    qa = AnswerEngine(db)
    scheduler = Scheduler(pipeline, args.interval)
    if not args.no_scheduler:
        scheduler.start()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(db, pipeline, qa))
    LOG.info("Dashboard: http://%s:%s", args.host, args.port)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.stop()
        server.server_close()


if __name__ == "__main__":
    main()
