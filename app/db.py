"""SQLite persistence. Every extracted claim retains a source document."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_timestamp(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return round(ordered[index], 2)


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def init_schema(self) -> None:
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sources (
                    id TEXT PRIMARY KEY, type TEXT NOT NULL, category TEXT NOT NULL,
                    url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                    config_hash TEXT NOT NULL DEFAULT '',
                    cursor TEXT, last_attempt TEXT, last_success TEXT,
                    fail_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'idle',
                    last_error TEXT
                );
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL REFERENCES sources(id),
                    external_id TEXT NOT NULL, canonical_id TEXT NOT NULL,
                    kind TEXT NOT NULL, title TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '',
                    published_at TEXT, updated_at TEXT, first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL, content_hash TEXT NOT NULL,
                    ai_score REAL NOT NULL DEFAULT 0, product TEXT NOT NULL DEFAULT '',
                    cvss REAL, severity TEXT NOT NULL DEFAULT '',
                    versions_json TEXT NOT NULL DEFAULT '[]',
                    fixed_versions_json TEXT NOT NULL DEFAULT '[]',
                    identifiers_json TEXT NOT NULL DEFAULT '[]',
                    refs_json TEXT NOT NULL DEFAULT '[]',
                    raw_json TEXT NOT NULL DEFAULT '{}',
                    mode TEXT NOT NULL DEFAULT 'live',
                    UNIQUE(source_id, external_id)
                );
                CREATE INDEX IF NOT EXISTS idx_documents_canonical ON documents(canonical_id);
                CREATE INDEX IF NOT EXISTS idx_documents_published ON documents(published_at DESC);
                CREATE INDEX IF NOT EXISTS idx_documents_kind ON documents(kind);
                CREATE TABLE IF NOT EXISTS claims (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT NOT NULL, predicate TEXT NOT NULL, object TEXT NOT NULL,
                    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                    evidence TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(subject,predicate,object,document_id)
                );
                CREATE INDEX IF NOT EXISTS idx_claim_subject ON claims(subject);
                CREATE INDEX IF NOT EXISTS idx_claim_object ON claims(object);
                CREATE INDEX IF NOT EXISTS idx_claim_alias_lookup ON claims(predicate,object,subject);
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
                    product TEXT NOT NULL, version TEXT NOT NULL,
                    exposure TEXT NOT NULL DEFAULT 'internal',
                    criticality INTEGER NOT NULL DEFAULT 3, owner TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, mode TEXT NOT NULL,
                    started_at TEXT NOT NULL, finished_at TEXT,
                    status TEXT NOT NULL, fetched INTEGER NOT NULL DEFAULT 0,
                    inserted INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0,
                    skipped INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER REFERENCES runs(id), agent TEXT NOT NULL,
                    action TEXT NOT NULL, status TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '', occurred_at TEXT NOT NULL
                );
                CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                    title, summary, body, product, content='documents', content_rowid='id',
                    tokenize='unicode61 remove_diacritics 2'
                );
                CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
                    INSERT INTO documents_fts(rowid,title,summary,body,product)
                    VALUES(new.id,new.title,new.summary,new.body,new.product);
                END;
                CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
                    INSERT INTO documents_fts(documents_fts,rowid,title,summary,body,product)
                    VALUES('delete',old.id,old.title,old.summary,old.body,old.product);
                END;
                CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
                    INSERT INTO documents_fts(documents_fts,rowid,title,summary,body,product)
                    VALUES('delete',old.id,old.title,old.summary,old.body,old.product);
                    INSERT INTO documents_fts(rowid,title,summary,body,product)
                    VALUES(new.id,new.title,new.summary,new.body,new.product);
                END;
            """)
            # Older databases predate the ingestion-mode column; migrate in place.
            columns = {row[1] for row in db.execute("PRAGMA table_info(documents)")}
            if "mode" not in columns:
                db.execute("ALTER TABLE documents ADD COLUMN mode TEXT NOT NULL DEFAULT 'live'")
            source_columns = {row[1] for row in db.execute("PRAGMA table_info(sources)")}
            if "config_hash" not in source_columns:
                db.execute("ALTER TABLE sources ADD COLUMN config_hash TEXT NOT NULL DEFAULT ''")

    def configure_sources(self, sources: list[dict[str, Any]]) -> None:
        with self.connect() as db:
            for source in sources:
                config_hash = hashlib.sha256(json_text(source).encode("utf-8")).hexdigest()
                db.execute("""
                    INSERT INTO sources(id,type,category,url,enabled,config_hash) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET type=excluded.type,
                    category=excluded.category,url=excluded.url,enabled=excluded.enabled,
                    cursor=CASE WHEN sources.config_hash!=excluded.config_hash
                        THEN NULL ELSE sources.cursor END,
                    last_success=CASE WHEN sources.config_hash!=excluded.config_hash
                        THEN NULL ELSE sources.last_success END,
                    status=CASE WHEN sources.config_hash!=excluded.config_hash
                        THEN 'idle' ELSE sources.status END,
                    fail_count=CASE WHEN sources.config_hash!=excluded.config_hash
                        THEN 0 ELSE sources.fail_count END,
                    last_error=CASE WHEN sources.config_hash!=excluded.config_hash
                        THEN NULL ELSE sources.last_error END,
                    config_hash=excluded.config_hash
                """, (source["id"], source["type"], source["category"],
                      source["url"], int(source.get("enabled", True)), config_hash))

    def source_rows(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM sources ORDER BY category,id")]

    def source_status(self, source_id: str, *, success: bool, cursor: str | None = None,
                      error: str = "") -> None:
        with self.connect() as db:
            db.execute("""
                UPDATE sources SET last_attempt=?, last_success=CASE WHEN ? THEN ? ELSE last_success END,
                    cursor=CASE WHEN ? THEN COALESCE(?,cursor) ELSE cursor END,
                    fail_count=CASE WHEN ? THEN 0 ELSE fail_count+1 END,
                    status=?, last_error=? WHERE id=?
            """, (utcnow(), int(success), utcnow(), int(success), cursor,
                  int(success), "healthy" if success else "error", error[:1000], source_id))

    def upsert_document(self, record: dict[str, Any]) -> tuple[int, str]:
        content_hash = hashlib.sha256(json_text(record).encode()).hexdigest()
        source_id = str(record["source_id"])
        external_id = str(record["external_id"])
        now = utcnow()
        mode = "demo" if record.get("mode") == "demo" else "live"
        values = (
            source_id, external_id, str(record["canonical_id"]), str(record["kind"]),
            str(record.get("title") or ""), str(record.get("summary") or ""),
            str(record.get("body") or ""), str(record.get("url") or ""),
            record.get("published_at"), record.get("updated_at"), now, now,
            content_hash, float(record.get("ai_score") or 0), str(record.get("product") or ""),
            record.get("cvss"), str(record.get("severity") or ""),
            json_text(record.get("versions") or []), json_text(record.get("fixed_versions") or []),
            json_text(record.get("identifiers") or []), json_text(record.get("refs") or []),
            json_text(record.get("raw") or {}), mode,
        )
        with self.connect() as db:
            existing = db.execute("SELECT id,content_hash FROM documents WHERE source_id=? AND external_id=?",
                                  (source_id, external_id)).fetchone()
            if existing and existing["content_hash"] == content_hash:
                db.execute("UPDATE documents SET last_seen=? WHERE id=?", (now, existing["id"]))
                return int(existing["id"]), "skipped"
            if existing:
                db.execute("""
                    UPDATE documents SET canonical_id=?,kind=?,title=?,summary=?,body=?,url=?,
                    published_at=?,updated_at=?,last_seen=?,content_hash=?,ai_score=?,product=?,
                    cvss=?,severity=?,versions_json=?,fixed_versions_json=?,identifiers_json=?,
                    refs_json=?,raw_json=?,mode=? WHERE id=?
                """, values[2:10] + values[11:] + (existing["id"],))
                db.execute("DELETE FROM claims WHERE document_id=?", (existing["id"],))
                return int(existing["id"]), "updated"
            cursor = db.execute("""
                INSERT INTO documents(source_id,external_id,canonical_id,kind,title,summary,body,url,
                    published_at,updated_at,first_seen,last_seen,content_hash,ai_score,product,cvss,
                    severity,versions_json,fixed_versions_json,identifiers_json,refs_json,raw_json,mode)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, values)
            return int(cursor.lastrowid), "inserted"

    def add_claim(self, subject: str, predicate: str, obj: str, document_id: int,
                  evidence: str, confidence: float) -> None:
        if not subject or not predicate or not obj:
            return
        with self.connect() as db:
            db.execute("""
                INSERT INTO claims(subject,predicate,object,document_id,evidence,confidence,created_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(subject,predicate,object,document_id)
                DO UPDATE SET evidence=excluded.evidence,confidence=excluded.confidence
            """, (subject, predicate, obj, document_id, evidence[:1200],
                  min(1.0, max(0.0, confidence)), utcnow()))

    def create_run(self, mode: str) -> int:
        with self.connect() as db:
            return int(db.execute("INSERT INTO runs(mode,started_at,status) VALUES(?,?,?)",
                                  (mode, utcnow(), "running")).lastrowid)

    def finish_run(self, run_id: int, status: str, counts: dict[str, int]) -> None:
        with self.connect() as db:
            db.execute("""UPDATE runs SET finished_at=?,status=?,fetched=?,inserted=?,updated=?,
                       skipped=?,errors=? WHERE id=?""",
                       (utcnow(), status, *(int(counts.get(k, 0)) for k in
                         ("fetched", "inserted", "updated", "skipped", "errors")), run_id))

    def run(self, run_id: int) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            return dict(row) if row else None

    def event(self, run_id: int | None, agent: str, action: str, status: str, detail: str = "") -> None:
        with self.connect() as db:
            db.execute("INSERT INTO events(run_id,agent,action,status,detail,occurred_at) VALUES(?,?,?,?,?,?)",
                       (run_id, agent, action, status, detail[:2000], utcnow()))

    def add_asset(self, asset: dict[str, Any]) -> int:
        if any(not isinstance(asset.get(key), str) or not asset[key].strip()
               for key in ("name", "product", "version")):
            raise ValueError("资产名称、产品与版本不能为空")
        name = asset["name"].strip()
        product = asset["product"].strip().lower()
        version = asset["version"].strip()
        criticality = asset.get("criticality", 3)
        if type(criticality) is not int or not 1 <= criticality <= 5:
            raise ValueError("criticality 必须为 1 到 5")
        exposure = asset.get("exposure", "internal")
        if not isinstance(exposure, str) or exposure not in {"internet", "internal", "isolated"}:
            raise ValueError("exposure 必须为 internet、internal 或 isolated")
        owner = asset.get("owner", "")
        if not isinstance(owner, str):
            raise ValueError("owner 必须为字符串")
        with self.connect() as db:
            cursor = db.execute("""
                INSERT INTO assets(name,product,version,exposure,criticality,owner,created_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET product=excluded.product,
                    version=excluded.version,exposure=excluded.exposure,
                    criticality=excluded.criticality,owner=excluded.owner
            """, (name, product, version, exposure, criticality,
                  owner, utcnow()))
            if cursor.lastrowid:
                return int(cursor.lastrowid)
            row = db.execute("SELECT id FROM assets WHERE name=?", (name,)).fetchone()
            return int(row["id"])

    def assets(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM assets ORDER BY criticality DESC,name")]

    def documents(self, *, query: str = "", kind: str = "", limit: int = 50) -> list[dict[str, Any]]:
        limit = min(max(int(limit), 1), 200)
        with self.connect() as db:
            if query:
                terms = [term for term in query.replace('"', ' ').split() if term]
                fts_query = " OR ".join('"' + term + '"' for term in terms[:8])
                if fts_query:
                    try:
                        rows = db.execute("""
                            SELECT d.* FROM documents_fts f JOIN documents d ON d.id=f.rowid
                            WHERE documents_fts MATCH ? AND (?='' OR d.kind=?)
                            ORDER BY bm25(documents_fts), d.published_at DESC LIMIT ?
                        """, (fts_query, kind, kind, limit)).fetchall()
                        if rows:
                            return [self._document_dict(row) for row in rows]
                    except sqlite3.OperationalError:
                        pass
                rows = self._like_search(db, query, kind, limit)
            else:
                rows = db.execute("""SELECT * FROM documents WHERE (?='' OR kind=?)
                    ORDER BY published_at DESC,id DESC LIMIT ?""", (kind, kind, limit)).fetchall()
            return [self._document_dict(row) for row in rows]

    def vulnerability_documents(self, *, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        """Page vulnerability records directly, without a mixed-kind 200-row cutoff."""
        limit = min(max(int(limit), 1), 500)
        offset = max(int(offset), 0)
        with self.connect() as db:
            rows = db.execute("""SELECT * FROM documents WHERE kind='vulnerability'
                ORDER BY published_at DESC,id DESC LIMIT ? OFFSET ?""",
                (limit, offset)).fetchall()
            return [self._document_dict(row) for row in rows]

    def search_vulnerability_documents(self, *, products: list[str] | None = None,
                                       limit: int = 400, offset: int = 0) -> list[dict[str, Any]]:
        """Product-topic scan over the whole vulnerability table.

        ``documents()`` mixes kinds and caps at the newest 200 rows, which can
        hide a relevant product behind an unrelated backlog. This query filters
        in SQL so portfolio answers stay reachable at any depth.
        """
        clauses, params = ["kind='vulnerability'"], []
        if products:
            placeholders = ",".join("?" for _ in products)
            clauses.append(f"product IN ({placeholders})")
            params.extend(products)
        with self.connect() as db:
            rows = db.execute(
                f"""SELECT * FROM documents WHERE {" AND ".join(clauses)}
                ORDER BY published_at DESC,id DESC LIMIT ? OFFSET ?""",
                (*params, min(max(int(limit), 1), 1000), max(0, int(offset)))).fetchall()
            return [self._document_dict(row) for row in rows]

    def known_products(self) -> list[str]:
        """Products seen in evidence, with vulnerability products first."""
        with self.connect() as db:
            rows = db.execute("""SELECT product,
                MAX(CASE WHEN kind='vulnerability' THEN 1 ELSE 0 END) AS has_vuln
                FROM documents WHERE product!='' GROUP BY product
                ORDER BY has_vuln DESC,LENGTH(product) DESC,product""").fetchall()
            return [str(row["product"]) for row in rows]

    def canonical_for_alias(self, alias: str) -> str | None:
        """Resolve a CVE/GHSA alias across the whole store; abstain if ambiguous."""
        identifier = str(alias).strip().upper()
        if not identifier:
            return None
        with self.connect() as db:
            rows = db.execute("""SELECT DISTINCT subject FROM claims
                WHERE predicate='alias' AND object=? LIMIT 2""", (identifier,)).fetchall()
            if len(rows) == 1:
                return str(rows[0]["subject"])
            if len(rows) > 1:
                return None
            row = db.execute("SELECT canonical_id FROM documents WHERE canonical_id=? LIMIT 1",
                             (identifier,)).fetchone()
            return str(row["canonical_id"]) if row else None

    @staticmethod
    def _like_search(db: sqlite3.Connection, query: str, kind: str,
                     limit: int) -> list[sqlite3.Row]:
        """Fallback substring search that works for unsegmented CJK text.

        FTS5's unicode61 tokenizer keeps a whole Chinese sentence as one token,
        so phrase queries rarely match. Split the query into CJK runs of 2+
        characters plus Latin words and match any of them as a substring.
        """
        cjk_runs = re.findall(r"[\u4e00-\u9fff]{2,}", query)
        latin_words = re.findall(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,}", query)
        tokens = list(dict.fromkeys(cjk_runs + latin_words))[:8] or [query[:100]]
        columns = ("title", "summary", "body", "product", "canonical_id")
        clauses, params = [], []
        for token in tokens:
            token_params = ["%" + token[:100] + "%"] * len(columns)
            clauses.append("(" + " OR ".join(f"{column} LIKE ?" for column in columns) + ")")
            params.extend(token_params)
        return db.execute(
            f"""SELECT * FROM documents WHERE ({" OR ".join(clauses)})
            AND (?='' OR kind=?) ORDER BY published_at DESC, id DESC LIMIT ?""",
            (*params, kind, kind, limit)).fetchall()

    @staticmethod
    def _document_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        for column in ("versions", "fixed_versions", "identifiers", "refs", "raw"):
            item[column] = json.loads(item.pop(column + "_json"))
        return item

    def document_group(self, canonical_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM documents WHERE canonical_id=? ORDER BY ai_score DESC",
                              (canonical_id,)).fetchall()
            return [self._document_dict(row) for row in rows]

    def related_documents(self, canonical_id: str, limit: int = 6) -> list[dict[str, Any]]:
        """Knowledge documents citing this identifier from outside its canonical group."""
        limit = min(max(int(limit), 1), 20)
        with self.connect() as db:
            rows = db.execute("""
                SELECT d.*, c.predicate AS match_predicate, c.confidence AS match_confidence
                FROM claims c JOIN documents d ON d.id = c.document_id
                WHERE c.subject = ? AND c.predicate = 'mentioned_in'
                    AND d.canonical_id != ?
                ORDER BY c.confidence DESC, d.published_at DESC LIMIT ?
            """, (canonical_id, canonical_id, limit)).fetchall()
            return [self._document_dict(row) for row in rows]

    def collection_latency_stats(self) -> dict[str, Any]:
        """Publish-to-collection delay in hours, split by ingestion mode.

        Demo snapshots import curated records long after publication, so their
        delay is labeled separately and must never be reported as live
        monitoring latency.
        """
        with self.connect() as db:
            rows = db.execute("""
                SELECT d.first_seen, d.published_at, d.mode AS ingest_mode
                FROM documents d
                WHERE d.published_at IS NOT NULL AND TRIM(d.published_at) != ''
            """).fetchall()
        buckets: dict[str, list[float]] = {"demo": [], "live": []}
        for row in rows:
            published = _parse_timestamp(str(row["published_at"]))
            collected = _parse_timestamp(str(row["first_seen"]))
            if published is None or collected is None:
                continue
            delay = (collected - published).total_seconds() / 3600
            if delay < 0:
                continue
            buckets["demo" if row["ingest_mode"] == "demo" else "live"].append(delay)

        def summarize(values: list[float]) -> dict[str, Any]:
            return {
                "samples": len(values),
                "p50_hours": _percentile(values, 0.50),
                "p95_hours": _percentile(values, 0.95),
                "max_hours": round(max(values), 2) if values else None,
            }

        return {
            "definition": "首次成功采集时间 - 来源首次公开发布时间，单位小时；负值与缺失时间戳剔除",
            "demo_snapshot": summarize(buckets["demo"]),
            "live": summarize(buckets["live"]),
        }

    def claims(self, subject: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as db:
            if subject:
                rows = db.execute("""SELECT c.*,d.title AS document_title,d.url AS document_url,
                    d.source_id,d.published_at FROM claims c JOIN documents d ON d.id=c.document_id
                    WHERE c.subject=? ORDER BY c.confidence DESC LIMIT ?""", (subject, limit)).fetchall()
            else:
                rows = db.execute("""SELECT c.*,d.title AS document_title,d.url AS document_url,
                    d.source_id,d.published_at FROM claims c JOIN documents d ON d.id=c.document_id
                    ORDER BY c.id DESC LIMIT ?""", (limit,)).fetchall()
            return [dict(row) for row in rows]

    def recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))]

    def recent_events(self, limit: int = 30) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    def stats(self) -> dict[str, Any]:
        with self.connect() as db:
            count = lambda table: db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            return {
                "documents": count("documents"), "vulnerabilities": db.execute(
                    "SELECT count(DISTINCT canonical_id) FROM documents WHERE kind='vulnerability'"
                ).fetchone()[0],
                "claims": count("claims"), "assets": count("assets"),
                "sources": count("sources"),
                "healthy_sources": db.execute("SELECT count(*) FROM sources WHERE status='healthy'").fetchone()[0],
                "latest_run": dict(row) if (row := db.execute(
                    "SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()) else None,
            }
