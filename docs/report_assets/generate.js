/* 知盾技术报告生成器：读取 content.json，输出 Word 文档。
 * 遵循 docx skill 规范：R1 封面配方、三节页码、TOC 三步流程、表格跨页控制。 */
const fs = require("fs");
const path = require("path");
const docxPackage = process.env.BUNDLED_NODE_MODULES
  ? path.join(process.env.BUNDLED_NODE_MODULES, "docx") : "docx";
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, ImageRun,
  Header, Footer, AlignmentType, HeadingLevel, PageNumber,
  BorderStyle, WidthType, ShadingType, TableLayoutType, SectionType, NumberFormat,
  VerticalAlign, TabStopType, LeaderType, TabStopPosition,
} = require(docxPackage);

const C = JSON.parse(fs.readFileSync(path.join(__dirname, "content.json"), "utf8"));
const tocEntries = JSON.parse(fs.readFileSync(path.join(__dirname, "toc_entries.json"), "utf8"));
const PAL = C.palette;

const F_HEAD = { ascii: "Arial", eastAsia: "STHeiti" };
const F_BODY = { ascii: "Times New Roman", eastAsia: "Songti SC" };
const F_MONO = { ascii: "Menlo", eastAsia: "Songti SC" };

const noBorders = {
  top: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
  bottom: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
  left: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
  right: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
};
const allNoBorders = { ...noBorders, insideHorizontal: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" }, insideVertical: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" } };

/* ---------------- 封面配方辅助（design-system.md） ---------------- */
function splitTitleLines(title, charsPerLine) {
  if (title.length <= charsPerLine) return [title];
  const breakAfter = new Set([..."，。、；：！？", ..."的与和及之在于为", ..."-_—–·/", ..." \t"]);
  const lines = [];
  let remaining = title;
  while (remaining.length > charsPerLine) {
    let breakAt = -1;
    for (let i = charsPerLine; i >= Math.floor(charsPerLine * 0.6); i--) {
      if (i < remaining.length && breakAfter.has(remaining[i - 1])) { breakAt = i; break; }
    }
    if (breakAt === -1) {
      const limit = Math.min(remaining.length, Math.ceil(charsPerLine * 1.3));
      for (let i = charsPerLine + 1; i < limit; i++) {
        if (breakAfter.has(remaining[i - 1])) { breakAt = i; break; }
      }
    }
    if (breakAt === -1) {
      breakAt = charsPerLine;
      const prevChar = remaining[breakAt - 1], nextChar = remaining[breakAt];
      if (prevChar && nextChar && !breakAfter.has(prevChar) && !breakAfter.has(nextChar)
          && /[\u4e00-\u9fff]/.test(prevChar) && /[\u4e00-\u9fff]/.test(nextChar)) breakAt -= 1;
    }
    lines.push(remaining.slice(0, breakAt).trim());
    remaining = remaining.slice(breakAt).trim();
  }
  if (remaining) lines.push(remaining);
  if (lines.length > 1 && lines[lines.length - 1].length <= 2) {
    const last = lines.pop();
    lines[lines.length - 1] += last;
  }
  return lines;
}
function calcTitleLayout(title, maxWidthTwips, preferredPt = 40, minPt = 24) {
  const charsPerLine = (pt) => Math.floor(maxWidthTwips / (pt * 20));
  let titlePt = preferredPt, lines;
  while (titlePt >= minPt) {
    const cpl = charsPerLine(titlePt);
    if (cpl < 2) { titlePt -= 2; continue; }
    lines = splitTitleLines(title, cpl);
    if (lines.length <= 3) break;
    titlePt -= 2;
  }
  if (!lines || lines.length > 3) { lines = splitTitleLines(title, charsPerLine(minPt)); titlePt = minPt; }
  return { titlePt, titleLines: lines };
}
function calcCoverSpacing(params) {
  const { titleLineCount = 1, titlePt = 36, hasSubtitle = false, hasEnglishLabel = false,
          metaLineCount = 0, fixedHeight = 800, pageHeight = 16838, marginTop = 0, marginBottom = 0 } = params;
  const SAFETY = 1200;
  const usableHeight = pageHeight - marginTop - marginBottom - SAFETY;
  const titleHeight = titleLineCount * (titlePt * 23 + 200);
  const subtitleHeight = hasSubtitle ? (12 * 23 + 600) : 0;
  const englishLabelHeight = hasEnglishLabel ? (9 * 23 + 600) : 0;
  const metaHeight = metaLineCount * (10 * 23 + 100);
  const implicitParaHeight = 3 * 300;
  const contentHeight = titleHeight + subtitleHeight + englishLabelHeight + metaHeight + fixedHeight + implicitParaHeight;
  const safeRemaining = Math.max(usableHeight - contentHeight, 400);
  const FOOTER_MIN = 800;
  const rawTop = Math.floor(safeRemaining * 0.45);
  const rawBottom = Math.floor(safeRemaining * 0.45);
  const bottomSpacing = Math.max(rawBottom, FOOTER_MIN);
  const topSpacing = Math.max(rawTop - Math.max(0, FOOTER_MIN - rawBottom), 400);
  const midSpacing = Math.max(safeRemaining - topSpacing - bottomSpacing, 0);
  return { topSpacing, midSpacing, bottomSpacing };
}
function buildCoverR1(config) {
  const P = config.palette;
  const padL = 1200, padR = 800;
  const availableWidth = 11906 - padL - padR - 300;
  const { titlePt, titleLines } = calcTitleLayout(config.title, availableWidth, 40, 24);
  const titleSize = titlePt * 2;
  const spacing = calcCoverSpacing({
    titleLineCount: titleLines.length, titlePt,
    hasSubtitle: !!config.subtitle, hasEnglishLabel: !!config.englishLabel,
    metaLineCount: (config.metaLines || []).length, fixedHeight: 400,
  });
  const accentLeft = { style: BorderStyle.SINGLE, size: 8, color: P.accent, space: 12 };
  const children = [];
  children.push(new Paragraph({ spacing: { before: spacing.topSpacing } }));
  if (config.englishLabel) {
    children.push(new Paragraph({
      indent: { left: padL, right: padR }, spacing: { after: 500 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: P.accent, space: 8 } },
      children: [new TextRun({ text: config.englishLabel.split("").join("  "), size: 18, color: P.accent, font: { ascii: "Calibri", eastAsia: "STHeiti" } })],
    }));
  }
  for (let i = 0; i < titleLines.length; i++) {
    children.push(new Paragraph({
      indent: { left: padL },
      spacing: { after: i < titleLines.length - 1 ? 100 : 300, line: Math.ceil(titlePt * 23), lineRule: "atLeast" },
      children: [new TextRun({ text: titleLines[i], size: titleSize, bold: true, color: P.titleColor, font: { eastAsia: "STHeiti", ascii: "Arial" } })],
    }));
  }
  if (config.subtitle) {
    children.push(new Paragraph({
      indent: { left: padL, right: padR }, spacing: { after: 800 },
      children: [new TextRun({ text: config.subtitle, size: 24, color: P.subtitleColor, font: { eastAsia: "SimSun", ascii: "Arial" } })],
    }));
  }
  for (const line of (config.metaLines || [])) {
    children.push(new Paragraph({
      indent: { left: padL + 200 }, spacing: { after: 80 },
      border: { left: accentLeft },
      children: [new TextRun({ text: line, size: 24, color: P.metaColor, font: { eastAsia: "SimSun", ascii: "Arial" } })],
    }));
  }
  children.push(new Paragraph({ spacing: { before: spacing.bottomSpacing } }));
  children.push(new Paragraph({
    indent: { left: padL, right: padR },
    border: { top: { style: BorderStyle.SINGLE, size: 2, color: P.accent, space: 8 } },
    spacing: { before: 200 },
    children: [
      new TextRun({ text: config.footerLeft || "", size: 16, color: P.footerColor, font: { ascii: "Arial", eastAsia: "Songti SC" } }),
      new TextRun({ text: "                                        " }),
      new TextRun({ text: config.footerRight || "", size: 16, color: P.footerColor, font: { ascii: "Arial", eastAsia: "Songti SC" } }),
    ],
  }));
  return [new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    layout: TableLayoutType.FIXED,
    borders: allNoBorders,
    rows: [new TableRow({
      height: { value: 16838, rule: "exact" },
      children: [new TableCell({ shading: { type: ShadingType.CLEAR, fill: P.bg }, borders: noBorders, children })],
    })],
  })];
}

/* ---------------- 正文块构建器 ---------------- */
function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1, pageBreakBefore: true,
    spacing: { before: 240, after: 200 }, alignment: AlignmentType.LEFT,
    children: [new TextRun({ text, bold: true, size: 32, color: PAL.primary, font: F_HEAD })],
  });
}
function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 140 },
    children: [new TextRun({ text, bold: true, size: 28, color: PAL.primary, font: F_HEAD })],
  });
}
function h3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 100 },
    children: [new TextRun({ text, bold: true, size: 26, color: PAL.secondary, font: F_HEAD })],
  });
}
function para(text) {
  return new Paragraph({
    alignment: AlignmentType.JUSTIFIED, indent: { firstLine: 480 }, spacing: { line: 312, after: 60 },
    children: [new TextRun({ text, size: 24, color: "000000", font: F_BODY })],
  });
}
function bulletItems(items, numbered) {
  return items.map((item, i) => new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    indent: { left: 480, hanging: 300 }, spacing: { line: 312, after: 40 },
    children: [
      new TextRun({ text: numbered ? `${i + 1}. ` : "\u2022 ", bold: true, size: 24, color: PAL.primary, font: F_BODY }),
      new TextRun({ text: item, size: 24, color: "000000", font: F_BODY }),
    ],
  }));
}
function captionPara(text, keepNext) {
  return new Paragraph({
    alignment: AlignmentType.CENTER, keepNext: !!keepNext, spacing: { before: 80, after: 120 },
    children: [new TextRun({ text, size: 21, color: PAL.secondary, font: F_BODY })],
  });
}
const CELL_MARGINS = { top: 60, bottom: 60, left: 110, right: 110 };
function tableBlock(block) {
  const widths = block.widths;
  const headerRow = new TableRow({
    tableHeader: true, cantSplit: true,
    children: block.header.map((cell, i) => new TableCell({
      width: { size: widths[i], type: WidthType.PERCENTAGE },
      shading: { type: ShadingType.CLEAR, fill: "E4EDF5" },
      margins: CELL_MARGINS, verticalAlign: VerticalAlign.CENTER,
      children: [new Paragraph({
        alignment: AlignmentType.CENTER, spacing: { line: 276 },
        children: [new TextRun({ text: cell, bold: true, size: 19, color: PAL.primary, font: F_HEAD })],
      })],
    })),
  });
  const rows = block.rows.map((row, ri) => new TableRow({
    cantSplit: true,
    children: row.map((cell, i) => new TableCell({
      width: { size: widths[i], type: WidthType.PERCENTAGE },
      shading: { type: ShadingType.CLEAR, fill: ri % 2 === 1 ? "F6F9FC" : "FFFFFF" },
      margins: CELL_MARGINS, verticalAlign: VerticalAlign.CENTER,
      children: [new Paragraph({
        alignment: AlignmentType.LEFT, spacing: { line: 276 },
        children: [new TextRun({ text: String(cell), size: 19, color: "1A2634", font: F_BODY })],
      })],
    })),
  }));
  return [
    captionPara(block.caption, true),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      layout: TableLayoutType.FIXED, borders: {
        top: { style: BorderStyle.SINGLE, size: 6, color: "9FB8CC" },
        bottom: { style: BorderStyle.SINGLE, size: 6, color: "9FB8CC" },
        left: { style: BorderStyle.SINGLE, size: 4, color: "C4D4E2" },
        right: { style: BorderStyle.SINGLE, size: 4, color: "C4D4E2" },
        insideHorizontal: { style: BorderStyle.SINGLE, size: 4, color: "C4D4E2" },
        insideVertical: { style: BorderStyle.SINGLE, size: 4, color: "C4D4E2" },
      },
      rows: [headerRow, ...rows],
    }),
    new Paragraph({ spacing: { after: 120 }, children: [] }),
  ];
}
function codeBlock(block) {
  const lines = block.x.split("\n");
  const runs = [];
  lines.forEach((line, i) => {
    runs.push(new TextRun({ text: line, size: 17, color: "17324A", font: F_MONO, break: i > 0 ? 1 : 0 }));
  });
  return [new Paragraph({
    alignment: AlignmentType.LEFT, spacing: { line: 252, before: 100, after: 160 },
    indent: { left: 240, right: 240 },
    shading: { type: ShadingType.CLEAR, fill: "F3F6F9" },
    border: {
      left: { style: BorderStyle.SINGLE, size: 12, color: PAL.accent, space: 8 },
      top: { style: BorderStyle.SINGLE, size: 2, color: "D7E1EA" }, bottom: { style: BorderStyle.SINGLE, size: 2, color: "D7E1EA" },
      right: { style: BorderStyle.SINGLE, size: 2, color: "D7E1EA" },
    },
    children: runs,
  })];
}
function figureBlock(block) {
  const data = fs.readFileSync(path.join(__dirname, block.src));
  return [
    new Paragraph({
      alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 160 },
      children: [new ImageRun({ type: "png", data, transformation: { width: block.w, height: block.h } })],
    }),
    captionPara(block.caption, false),
  ];
}
function renderBlocks(blocks) {
  const out = [];
  for (const block of blocks) {
    if (block.t === "h2") out.push(h2(block.x));
    else if (block.t === "h3") out.push(h3(block.x));
    else if (block.t === "p") out.push(para(block.x));
    else if (block.t === "bullets") out.push(...bulletItems(block.items, false));
    else if (block.t === "numbers") out.push(...bulletItems(block.items, true));
    else if (block.t === "table") out.push(...tableBlock(block));
    else if (block.t === "code") out.push(...codeBlock(block));
    else if (block.t === "fig") out.push(...figureBlock(block));
  }
  return out;
}

/* ---------------- 前置部分：核心亮点预览 + 目录 ---------------- */
function buildFrontMatter() {
  const HL = C.highlights;
  const out = [];
  out.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { before: 240, after: 240 },
    children: [new TextRun({ text: HL.title, bold: true, size: 32, color: PAL.primary, font: F_HEAD })],
  }));
  out.push(para(HL.intro));
  for (const card of HL.cards) {
    out.push(new Paragraph({
      alignment: AlignmentType.JUSTIFIED, indent: { left: 360, hanging: 0 }, spacing: { line: 312, before: 120, after: 40 },
      border: { left: { style: BorderStyle.SINGLE, size: 14, color: PAL.accent, space: 10 } },
      children: [
        new TextRun({ text: `\u25B8 ${card.k}\u3000`, bold: true, size: 23, color: PAL.primary, font: F_HEAD }),
        new TextRun({ text: card.v, size: 22, color: "1A2634", font: F_BODY }),
      ],
    }));
  }
  out.push(new Paragraph({
    spacing: { before: 200 },
    children: [new TextRun({ text: "（正文目录见下页；各章含完整设计图、数据表与实测结果。）", italics: true, size: 19, color: "7A8CA0", font: F_BODY }), new (require(docxPackage).PageBreak)()],
  }));
  // 目录页
  out.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { before: 480, after: 360 },
    children: [new TextRun({ text: "目  录", bold: true, size: 32, color: PAL.primary, font: F_HEAD })],
  }));
  for (const entry of tocEntries) {
    out.push(new Paragraph({
      indent: { left: entry.level === 2 ? 340 : 0 },
      spacing: { before: entry.level === 1 ? 75 : 0, after: entry.level === 1 ? 50 : 20 },
      tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX, leader: LeaderType.DOT }],
      children: [
        new TextRun({ text: entry.text, bold: entry.level === 1, size: entry.level === 1 ? 20 : 18, font: F_BODY, color: PAL.primary }),
        new TextRun({ text: `\t${entry.page}`, size: 18, font: F_BODY, color: PAL.primary }),
      ],
    }));
  }
  out.push(new Paragraph({ children: [new (require(docxPackage).PageBreak)()] }));
  return out;
}

/* ---------------- 组装文档 ---------------- */
const bodyChildren = [];
C.chapters.forEach((chapter, idx) => {
  bodyChildren.push(new Paragraph({
    heading: HeadingLevel.HEADING_1, pageBreakBefore: idx > 0,
    spacing: { before: 240, after: 200 },
    children: [new TextRun({ text: chapter.title, bold: true, size: 32, color: PAL.primary, font: F_HEAD })],
  }));
  bodyChildren.push(...renderBlocks(chapter.blocks));
});

function romanFooter() {
  return new Footer({ children: [new Paragraph({
    alignment: AlignmentType.CENTER,
    children: [new TextRun({ children: [PageNumber.CURRENT], size: 18, color: PAL.secondary, font: F_BODY })],
  })] });
}
function arabicFooter() {
  return new Footer({ children: [new Paragraph({
    alignment: AlignmentType.CENTER,
    children: [
      new TextRun({ text: "第 ", size: 18, color: PAL.secondary, font: F_BODY }),
      new TextRun({ children: [PageNumber.CURRENT], size: 18, color: PAL.secondary, font: F_BODY }),
      new TextRun({ text: " 页", size: 18, color: PAL.secondary, font: F_BODY }),
    ],
  })] });
}
function docHeader() {
  return new Header({ children: [new Paragraph({
    alignment: AlignmentType.RIGHT,
    border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "C4D4E2", space: 4 } },
    children: [new TextRun({ text: "知盾 AI 安全知识情报系统 · 技术报告", size: 16, color: "7A8CA0", font: F_BODY })],
  })] });
}

const pgSize = { width: 11906, height: 16838 };
const pgMargin = { top: 1440, bottom: 1440, left: 1701, right: 1417 };

const doc = new Document({
  creator: "Zhidun Team",
  title: C.cover.title,
  styles: {
    default: {
      document: { run: { font: F_BODY, size: 24, color: "000000" }, paragraph: { spacing: { line: 312 } } },
      heading1: { run: { font: F_HEAD, size: 32, bold: true, color: PAL.primary }, paragraph: { spacing: { before: 240, after: 200 }, outlineLevel: 0 } },
      heading2: { run: { font: F_HEAD, size: 28, bold: true, color: PAL.primary }, paragraph: { spacing: { before: 280, after: 140 }, outlineLevel: 1 } },
      heading3: { run: { font: F_HEAD, size: 26, bold: true, color: PAL.secondary }, paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 } },
    },
  },
  features: { updateFields: true },
  sections: [
    { // 封面：边距为 0，无页码
      properties: { page: { size: pgSize, margin: { top: 0, bottom: 0, left: 0, right: 0 } } },
      children: buildCoverR1({ ...C.cover, palette: PAL }),
    },
    { // 前置：亮点预览 + 目录，罗马页码
      properties: {
        type: SectionType.NEXT_PAGE,
        page: { size: pgSize, margin: pgMargin, pageNumbers: { start: 1, formatType: NumberFormat.UPPER_ROMAN } },
      },
      headers: { default: docHeader() },
      footers: { default: romanFooter() },
      children: buildFrontMatter(),
    },
    { // 正文：阿拉伯页码从 1 起
      properties: {
        type: SectionType.NEXT_PAGE,
        page: { size: pgSize, margin: pgMargin, pageNumbers: { start: 1, formatType: NumberFormat.DECIMAL } },
      },
      headers: { default: docHeader() },
      footers: { default: arabicFooter() },
      children: bodyChildren,
    },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  const out = path.join(__dirname, "知盾AI安全知识情报系统技术报告.docx");
  fs.writeFileSync(out, buf);
  console.log("WROTE", out, buf.length, "bytes");
});
