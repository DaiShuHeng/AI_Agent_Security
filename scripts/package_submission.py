#!/usr/bin/env python3
"""Build a reviewable source archive from an explicit public-file allowlist.

Local credentials, live databases, caches, installed dependencies and generated
report copies are deliberately outside the manifest. Reports are delivered as
separate files in 交付物/.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "交付物" / "知盾AI赛题9_源码审阅包.zip"
ROOT_FILES = {"README.md", "Dockerfile", "compose.yaml", ".gitignore", ".env.example"}
SOURCE_SUFFIXES = {".py", ".js", ".css", ".html", ".json", ".md", ".png", ".gz", ".txt", ".yml", ".yaml"}
PUBLIC_DIRS = {"app", "config", "data", "docs", "scripts", "tests", "web", ".github"}
REPORT_GENERATED = {".docx", ".pdf", ".pptx"}


def source_files() -> list[Path]:
    selected = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(ROOT)
        if any(part in {"__pycache__", "node_modules"} for part in relative.parts):
            continue
        if len(relative.parts) == 1:
            if relative.name in ROOT_FILES:
                selected.append(path)
            continue
        if relative.parts[0] not in PUBLIC_DIRS:
            continue
        if relative.name.startswith(".env") or relative.suffix in REPORT_GENERATED:
            continue
        if relative.parts[0] == "data" and relative.name not in {
            "demo_assets.json", "demo_records.json", "eval_gold.json"
        }:
            continue
        if relative.suffix in SOURCE_SUFFIXES:
            selected.append(path)
    return sorted(selected, key=lambda path: str(path.relative_to(ROOT)))


def main() -> None:
    files = source_files()
    OUTPUT.parent.mkdir(exist_ok=True)
    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            archive.write(path, path.relative_to(ROOT))
    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    print(f"{OUTPUT} | {len(files)} files | SHA-256 {digest}")


if __name__ == "__main__":
    main()
