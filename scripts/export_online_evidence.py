#!/usr/bin/env python3
"""Export a reproducible, public-only collection snapshot from a dedicated SQLite DB.

Do not run on a database containing private assets or question history. The
archive includes normalized source records but no credentials or local assets.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import platform
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def export(database: Path, output: Path) -> dict:
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        runs = [dict(row) for row in db.execute(
            "SELECT * FROM runs WHERE mode='live' ORDER BY id"
        )]
        sources = [dict(row) for row in db.execute(
            """SELECT id,type,category,url,config_hash,cursor,last_attempt,
                      last_success,status,last_error FROM sources ORDER BY id"""
        )]
        records = [dict(row) for row in db.execute(
            """SELECT source_id,external_id,canonical_id,kind,title,url,
                      published_at,updated_at,first_seen,last_seen,content_hash,
                      mode,raw_json FROM documents WHERE mode='live'
               ORDER BY source_id,external_id"""
        )]
        events = [dict(row) for row in db.execute(
            """SELECT run_id,agent,action,status,detail,occurred_at FROM events
               WHERE run_id IN (SELECT id FROM runs WHERE mode='live') ORDER BY id"""
        )]
        claim_count = db.execute(
            """SELECT COUNT(*) FROM claims c JOIN documents d ON d.id=c.document_id
               WHERE d.mode='live'"""
        ).fetchone()[0]
        vulnerabilities = db.execute(
            """SELECT COUNT(DISTINCT canonical_id) FROM documents
               WHERE mode='live' AND kind='vulnerability'"""
        ).fetchone()[0]
        claims_by_predicate = {row[0]: row[1] for row in db.execute(
            """SELECT c.predicate,COUNT(*) FROM claims c
               JOIN documents d ON d.id=c.document_id
               WHERE d.mode='live' GROUP BY c.predicate ORDER BY c.predicate"""
        )}
    by_source: dict[str, int] = {}
    for record in records:
        by_source[record["source_id"]] = by_source.get(record["source_id"], 0) + 1
    payload = {
        "scope": "public_online_collection_development_snapshot",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                        "platform": platform.platform()},
        "limitations": [
            "仅保留数据库中的来源记录原字段与任务事件，非逐字节 HTTP 响应归档。",
            "一次或少量手动采集不能证明持续实时覆盖，也不能证明赛题的 7 类来源或 ≤6 小时时效。",
            "首次采集时间减来源日期只是当前快照的历史积压延迟，不是稳定监测延迟。",
        ],
        "run_count": len(runs), "record_count": len(records),
        "claim_count": claim_count, "vulnerability_count": vulnerabilities,
        "claims_by_predicate": claims_by_predicate,
        "record_count_by_source": by_source,
        "runs": runs, "sources": sources, "events": events, "records": records,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=1).encode("utf-8")
    with gzip.open(output, "wb", compresslevel=9) as stream:
        stream.write(serialized)
    return {"path": str(output), "bytes": output.stat().st_size,
            "json_sha256": hashlib.sha256(serialized).hexdigest(),
            "run_count": len(runs), "record_count": len(records),
            "claim_count": claim_count, "vulnerability_count": vulnerabilities,
            "record_count_by_source": by_source}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.db.is_file():
        parser.error(f"数据库不存在：{args.db}")
    print(json.dumps(export(args.db, args.output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
