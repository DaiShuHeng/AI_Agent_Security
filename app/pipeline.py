"""Auditable monitor, triage, enrichment, verification and indexing agents."""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .db import Database, utcnow
from .intelligence import ai_relevance, normalize_record, record_claims
LOG = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULNERABILITY_ID = re.compile(
    r"(?:CVE-\d{4}-\d{4,19}|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})", re.I)
OSV_NATIVE_ID = re.compile(r"(?:OSV|PYSEC|GO|RUSTSEC)-[A-Z0-9._-]{4,100}", re.I)


def load_sources(path: str | Path | None = None) -> list[dict[str, Any]]:
    path = Path(path) if path else PROJECT_ROOT / "config" / "sources.json"
    return json.loads(path.read_text(encoding="utf-8"))


def load_demo_records(path: str | Path | None = None) -> list[dict[str, Any]]:
    path = Path(path) if path else PROJECT_ROOT / "data" / "demo_records.json"
    return json.loads(path.read_text(encoding="utf-8"))


class Pipeline:
    def __init__(self, db: Database, sources: list[dict[str, Any]] | None = None):
        self.db = db
        self.sources = sources if sources is not None else load_sources()
        self.db.configure_sources(self.sources)
        self._lock = threading.Lock()

    def _ingest(self, raw: dict[str, Any], run_id: int, mode: str = "live") -> str:
        record = normalize_record(raw)
        record["mode"] = mode
        canonical = record["canonical_id"]
        source_type = next((source.get("type") for source in self.sources
                            if source.get("id") == record.get("source_id")), None)
        raw_evidence = record.get("raw")
        native_id = str(raw_evidence.get("id") or "").upper() if isinstance(raw_evidence, dict) else ""
        if (record["kind"] == "vulnerability" and source_type == "osv"
                and not VULNERABILITY_ID.fullmatch(canonical)
                and OSV_NATIVE_ID.fullmatch(native_id)
                and str(record.get("external_id") or "").upper().startswith(native_id + "::")):
            canonical = record["canonical_id"] = native_id
        self.db.event(run_id, "分诊代理", "AI 相关性与实体归一", "ok",
                      f"{record['external_id']} → {canonical}; AI={record['ai_score']:.2f}")
        if record["ai_score"] < 0.33:
            # 单个 AI 术语命中得 1/3≈0.333；阈值必须低于该值，否则真实
            # AI 安全公告（如仅标题含 "agentic"）会被整条误杀。
            self.db.event(run_id, "分诊代理", "过滤非 AI 安全记录", "skipped", str(record["external_id"]))
            return "skipped"
        if not record.get("title") or not record.get("external_id"):
            self.db.event(run_id, "核验代理", "字段完整性", "rejected", str(record.get("external_id")))
            return "skipped"
        if (record["kind"] == "vulnerability" and
                not (VULNERABILITY_ID.fullmatch(canonical) or
                     (source_type == "osv" and OSV_NATIVE_ID.fullmatch(canonical)))):
            self.db.event(run_id, "核验代理", "漏洞标识校验", "rejected", str(record["external_id"]))
            return "skipped"
        document_id, state = self.db.upsert_document(record)
        # Upsert and claim extraction use separate SQLite transactions. If a
        # previous attempt stopped after only some claims were written, the
        # next identical document is "skipped". Replaying idempotent claims
        # here repairs that partial write before the source cursor advances.
        claim_stats = record_claims(self.db, document_id, record)
        if state != "skipped":
            self.db.event(run_id, "富化代理", "提取证据化声明", "ok",
                          f"{canonical}: {claim_stats['total']} 条事实; 来源={record['source_id']}")
            if claim_stats["cross_mentions"]:
                title = str(record.get("title") or record.get("external_id") or "")[:60]
                self.db.event(run_id, "关联推理代理", "跨文档漏洞关联", "ok",
                              f"《{title}》提及 {claim_stats['cross_mentions']} 个其他漏洞标识，"
                              "已建立 mentioned_in 反向关联")
        self.db.event(run_id, "索引代理", "增量去重及索引", state, f"document={document_id}")
        return state

    def run_demo(self, records: list[dict[str, Any]] | None = None,
                 assets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("已有采集任务正在运行")
        try:
            records = records if records is not None else load_demo_records()
            if assets is None:
                assets_path = PROJECT_ROOT / "data" / "demo_assets.json"
                assets = json.loads(assets_path.read_text(encoding="utf-8"))
            demo_sources = {}
            configured_ids = {row["id"] for row in self.db.source_rows()}
            for item in records:
                source_id = str(item["source_id"])
                demo_sources[source_id] = {"id": source_id, "type": "demo",
                                           "category": item.get("source_category", "demo"),
                                           "url": item.get("url", "https://example.invalid"),
                                           "enabled": False}
            self.db.configure_sources([source for source in demo_sources.values()
                                       if source["id"] not in configured_ids])
            run_id = self.db.create_run("demo")
            counts = {key: 0 for key in ("fetched", "inserted", "updated", "skipped", "errors")}
            self.db.event(run_id, "监测代理", "载入离线公开来源快照", "ok", f"{len(records)} 条记录")
            try:
                for item in records:
                    counts["fetched"] += 1
                    state = self._ingest(item, run_id, mode="demo")
                    counts[state] += 1
                for asset in assets:
                    self.db.add_asset(asset)
                self.db.event(run_id, "资产代理", "本地授权资产映射", "ok", f"{len(assets)} 项演示资产")
                with self.db.connect() as connection:
                    for source_id in demo_sources:
                        if source_id not in configured_ids:
                            connection.execute("UPDATE sources SET status='demo',last_success=? WHERE id=?",
                                               (utcnow(), source_id))
                status = "success"
            except Exception as exc:
                counts["errors"] += 1
                status = "failed"
                self.db.event(run_id, "调度代理", "离线导入", "error", str(exc))
                raise
            finally:
                self.db.finish_run(run_id, status, counts)
            return {"run_id": run_id, "status": status, **counts}
        finally:
            self._lock.release()

    def _enrich_epss(self, run_id: int, canonicals: list[str]) -> int:
        """Live-only impact assessment: FIRST EPSS exploitation probability.

        Adds one evidence-backed claim per newly seen CVE; CVEs that already
        carry an EPSS claim are skipped so the step stays idempotent.
        """
        if not canonicals:
            return 0
        from .connectors import fetch_epss

        known: set[str] = set()
        for canonical in canonicals[:200]:
            for claim in self.db.claims(canonical, limit=200):
                if claim["predicate"] == "epss":
                    known.add(canonical)
                    break
        pending = [c for c in dict.fromkeys(canonicals) if c.startswith("CVE-") and c not in known]
        if not pending:
            return 0
        self.db.event(run_id, "影响评估代理", "EPSS 利用可能性查询", "running",
                      f"{len(pending)} 个 CVE 待评估")
        try:
            scores = fetch_epss(pending)
        except Exception as exc:
            self.db.event(run_id, "影响评估代理", "EPSS 利用可能性查询", "error", str(exc)[:400])
            return 0
        written = 0
        for canonical, score in scores.items():
            documents = self.db.document_group(canonical)
            if not documents:
                continue
            self.db.add_claim(
                canonical, "epss",
                f"{score['epss']:.4f}（percentile {score['percentile']:.3f}，{score['date']}）",
                documents[0]["id"],
                "FIRST EPSS 官方评分：未来 30 天内被利用的概率（0-1）", 0.95)
            written += 1
        self.db.event(run_id, "影响评估代理", "EPSS 利用可能性查询", "ok" if written else "skipped",
                      f"新增 {written} 条 EPSS 评分；{len(pending) - written} 个 CVE 暂无评分")
        return written

    def _reserve_live(self, selected_source: str | None) -> int:
        if selected_source is not None and (not isinstance(selected_source, str) or
                selected_source not in {s['id'] for s in self.sources if s.get('enabled', True)}):
            raise ValueError("未知或未启用的数据源")
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("已有采集任务正在运行")
        try:
            return self.db.create_run("live")
        except Exception:
            self._lock.release()
            raise

    def start_live(self, selected_source: str | None = None) -> int:
        # Admission and run creation happen before acknowledging the HTTP request.
        run_id = self._reserve_live(selected_source)
        def worker():
            try:
                self._execute_live(run_id, selected_source)
            except Exception:
                LOG.exception("Background live collection failed")
        try:
            threading.Thread(target=worker, daemon=True, name=f"collect-{run_id}").start()
        except Exception:
            try:
                self.db.finish_run(run_id, "failed", {"errors": 1})
            finally:
                self._lock.release()
            raise
        return run_id

    def run_live(self, selected_source: str | None = None) -> dict[str, Any]:
        return self._execute_live(self._reserve_live(selected_source), selected_source)

    def _execute_live(self, run_id: int, selected_source: str | None) -> dict[str, Any]:
        counts = {key: 0 for key in ("fetched", "inserted", "updated", "skipped", "errors")}
        status = "failed"
        try:
            from .connectors import fetch_source

            cursors = {row["id"]: row["cursor"] for row in self.db.source_rows()}
            sources = [source for source in self.sources if source.get("enabled", True)
                       and (selected_source is None or source["id"] == selected_source)]
            touched: list[str] = []
            self.db.event(run_id, "调度代理", "规划采集", "ok",
                          f"sources={','.join(source['id'] for source in sources)}")
            try:
                for source in sources:
                    since = cursors.get(source["id"])
                    if since:
                        try:
                            # Overlap tolerates out-of-order publication; document upsert is idempotent.
                            since = (datetime.fromisoformat(since.replace("Z", "+00:00"))
                                     - timedelta(minutes=10)).isoformat()
                        except ValueError:
                            since = None
                    self.db.event(run_id, "监测代理", "增量采集", "running", source["id"])
                    error = ""
                    for attempt in range(3):
                        try:
                            # A watermark taken after processing can jump over
                            # records published during a long collection run.
                            attempt_started_at = utcnow()
                            items = fetch_source(source, since=since,
                                                 limit=source.get("limit", 200))
                            for item in items:
                                counts["fetched"] += 1
                                state = self._ingest(item, run_id)
                                counts[state] += 1
                                if state in {"inserted", "updated"}:
                                    touched.append(normalize_record(item)["canonical_id"])
                            self.db.source_status(source["id"], success=True,
                                                  cursor=attempt_started_at)
                            self.db.event(run_id, "监测代理", "增量采集", "ok",
                                          f"{source['id']}: {len(items)} 条; attempt={attempt + 1}")
                            break
                        except Exception as exc:
                            error = f"{type(exc).__name__}: {exc}"
                            LOG.warning("Source %s failed (%s/3): %s", source["id"], attempt + 1, error)
                            self.db.event(run_id, "自愈代理", "失败重试", "retry" if attempt < 2 else "error",
                                          f"{source['id']}: {error}")
                            if attempt < 2:
                                time.sleep(min(2 ** attempt, 4))
                    else:
                        counts["errors"] += 1
                        self.db.source_status(source["id"], success=False, error=error)
                self._enrich_epss(run_id, touched)
                status = "partial" if counts["errors"] else "success"
            except Exception as exc:
                counts["errors"] += 1
                status = "failed"
                self.db.event(run_id, "调度代理", "采集任务", "error", str(exc))
                raise
            return {"run_id": run_id, "status": status, **counts}
        finally:
            try:
                self.db.finish_run(run_id, status, counts)
            finally:
                self._lock.release()


class Scheduler:
    """Fixed interval polling; does not claim streaming real-time semantics."""

    def __init__(self, pipeline: Pipeline, interval_seconds: int = 1800):
        self.pipeline = pipeline
        self.interval_seconds = max(300, int(interval_seconds))
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._run, name="intel-scheduler", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.wait(self.interval_seconds):
            try:
                self.pipeline.run_live()
            except Exception:
                LOG.exception("Scheduled collection failed")

    def stop(self) -> None:
        self.stop_event.set()
