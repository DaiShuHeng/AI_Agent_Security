#!/usr/bin/env python3
"""Rebuild report and presentation, then sync the four contest deliverables."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from build_report import HERE, SOFFICE, libreoffice_env, main as build_report


ROOT = HERE.parents[1]
DELIVERABLES = ROOT / "交付物"
PPTX = HERE / "知盾AI安全知识情报系统讲解PPT.pptx"


def main() -> None:
    if not Path(SOFFICE).is_file():
        raise SystemExit("未找到捆绑的 LibreOffice；请设置 BUNDLED_SOFFICE 为可信的 soffice 绝对路径")
    build_report()
    subprocess.run(["node", "gen_ppt.js"], cwd=HERE, check=True)
    subprocess.run(
        [SOFFICE, "--headless", "-env:UserInstallation=file:///tmp/loprofile-zhidun-ppt",
         "--convert-to", "pdf", str(PPTX), "--outdir", str(HERE)],
        cwd=HERE, check=True, env=libreoffice_env(), capture_output=True,
    )
    DELIVERABLES.mkdir(exist_ok=True)
    for suffix in ("技术报告.docx", "技术报告.pdf", "讲解PPT.pptx", "讲解PPT.pdf"):
        source = HERE / f"知盾AI安全知识情报系统{suffix}"
        shutil.copy2(source, DELIVERABLES / source.name)
        print(f"交付物：{source.name} ({source.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
