#!/usr/bin/env python3
"""两遍生成技术报告与静态目录页码。

用法：python3 build_report.py   （在 docs/report_assets 目录下执行）
依赖：node + docx（npm install）、pypdf、LibreOffice。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from pypdf import PdfReader

HERE = Path(__file__).resolve().parent
DOCX = HERE / "知盾AI安全知识情报系统技术报告.docx"
PDF = HERE / "知盾AI安全知识情报系统技术报告.pdf"
SOFFICE = os.environ.get(
    "BUNDLED_SOFFICE",
    str(Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/bin/override/soffice"),
)
LO_PROFILE = "-env:UserInstallation=file:///tmp/loprofile3"


def footer_patch(path: Path) -> None:
    tmp = path.with_suffix(".tmp")
    with zipfile.ZipFile(path) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename.startswith("word/footer") and item.filename.endswith(".xml"):
                xml = data.decode("utf-8")
                fmt = "arabic" if "第" in xml else "ROMAN"
                xml = re.sub(r"(<w:instrText[^>]*>)\s*PAGE\s*(</w:instrText>)",
                             rf"\1 PAGE \\* {fmt} \\* MERGEFORMAT \2", xml)
                data = xml.encode("utf-8")
            elif item.filename == "word/document.xml":
                data = data.decode("utf-8").replace("<w:pgNumType/>", "").encode("utf-8")
            zout.writestr(item, data)
    shutil.move(tmp, path)


def libreoffice_env() -> dict[str, str]:
    env = os.environ.copy()
    if sys.platform == "darwin" and not env.get("FONTCONFIG_FILE"):
        font_conf = Path(tempfile.gettempdir()) / "zhidun-report-fontconfig.xml"
        font_conf.write_text(
            '<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd">'
            '<fontconfig><dir>/System/Library/Fonts</dir>'
            '<dir>/System/Library/Fonts/Supplemental</dir>'
            '<dir>/Library/Fonts</dir>'
            '<cachedir>/tmp/zhidun-report-fontcache</cachedir></fontconfig>',
            encoding="utf-8",
        )
        env["FONTCONFIG_FILE"] = str(font_conf)
    return env


def build(entries: list[dict]) -> None:
    (HERE / "toc_entries.json").write_text(
        json.dumps(entries, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    subprocess.run(["node", "generate.js"], check=True, capture_output=True, cwd=HERE)
    footer_patch(DOCX)
    subprocess.run([SOFFICE, "--headless", LO_PROFILE, "--convert-to", "pdf",
                    str(DOCX), "--outdir", str(HERE)], check=True, capture_output=True,
                   env=libreoffice_env())


def heading_list() -> list[tuple[int, str]]:
    content = json.loads((HERE / "content.json").read_text(encoding="utf-8"))
    headings = []
    for ch in content["chapters"]:
        headings.append((1, ch["title"]))
        headings.extend((2, b["x"]) for b in ch["blocks"] if b.get("t") == "h2")
    return headings


def main() -> None:
    headings = heading_list()
    dummy = [{"level": l, "text": t, "page": "1"} for l, t in headings]

    build(dummy)  # 第一遍：确定分页
    doc = PdfReader(PDF)
    start = next(i for i, p in enumerate(doc.pages) if re.search(r"第\s*1\s*页", p.extract_text()))
    searchable = [re.sub(r"\s+", "", p.extract_text()) for p in doc.pages]
    real, last = [], start + 1
    for level, text in headings:
        needle = re.sub(r"\s+", "", text)
        found = next((pno + 1 for pno in range(start, len(doc.pages))
                      if needle in searchable[pno]), None)
        page = found or last
        last = page
        real.append({"level": level, "text": text, "page": str(page - start)})
    print(f"pass1 body_start={start + 1} last={real[-1]}")

    build(real)  # 第二遍：真实页码
    doc = PdfReader(PDF)
    start2 = next(i for i, p in enumerate(doc.pages) if re.search(r"第\s*1\s*页", p.extract_text()))
    stable = start == start2
    print(f"pass2 pages={len(doc.pages)} body_start={start2 + 1} stable={stable}")
    if not stable:
        raise SystemExit("分页未收敛，请再运行一次")


if __name__ == "__main__":
    main()
