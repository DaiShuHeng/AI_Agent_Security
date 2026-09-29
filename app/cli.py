"""Command line entry points for reproducible import, collection and Q&A."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from .db import Database
from .pipeline import PROJECT_ROOT, Pipeline
from .qa import AnswerEngine
from . import llm


def main() -> None:
    parser = argparse.ArgumentParser(description="知盾 AI 安全情报 CLI")
    parser.add_argument("--db", default=str(PROJECT_ROOT / "data" / "zhidun.sqlite3"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="导入可核验的离线演示快照")
    collect = sub.add_parser("collect", help="在线增量采集")
    collect.add_argument("--source", help="仅运行一个配置源 ID")
    ask = sub.add_parser("ask", help="证据化问答")
    ask.add_argument("question")
    asset_import = sub.add_parser("import-assets", help="从授权 CSV 导入本地资产清单")
    asset_import.add_argument("csv_file", type=Path)
    sub.add_parser("stats", help="查看数据库统计")
    args = parser.parse_args()
    db = Database(Path(args.db))
    pipeline = Pipeline(db)
    if args.command == "demo":
        result = pipeline.run_demo()
    elif args.command == "collect":
        result = pipeline.run_live(selected_source=args.source)
    elif args.command == "ask":
        llm.load_local_config(PROJECT_ROOT / ".env.local")
        result = AnswerEngine(db).ask(args.question)
    elif args.command == "import-assets":
        imported = 0
        with args.csv_file.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            required = {"name", "product", "version"}
            if not required <= set(reader.fieldnames or []):
                raise SystemExit("CSV 必须包含 name,product,version 列")
            for row in reader:
                db.add_asset(row)
                imported += 1
        result = {"imported": imported, "note": "仅处理已授权的本地资产清单，不执行网络扫描"}
    else:
        result = db.stats()
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
