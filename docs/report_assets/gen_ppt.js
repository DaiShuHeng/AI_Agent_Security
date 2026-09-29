/* 知盾技术讲解 PPT —— 深蓝安全主题，三明治结构（深色封面/结尾 + 浅色内容页） */
const path = require("path");
const pptxgen = require(process.env.BUNDLED_NODE_MODULES
  ? path.join(process.env.BUNDLED_NODE_MODULES, "pptxgenjs") : "pptxgenjs");

const P = {
  DARK: "0B1F33", DARK2: "122A44", LIGHT: "FFFFFF", PANEL: "EAF2F9", PANEL2: "F4F8FC",
  PRIMARY: "16466E", ACCENT: "3D9BE9", TEXT: "15243A", MUTED: "5B6B7C",
  GOOD: "2F8F6B", WARN: "C97B4A", ON_DARK: "E8F1F9", ON_DARK_MUTED: "9FB6CC",
};
const F = "Heiti SC";
const W = 13.33, H = 7.5, M = 0.55;

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.author = "Zhidun Team";
pres.title = "知盾：智能体驱动的AI安全知识情报系统";

const bu = () => ({ code: "25B8", indent: 12 });
const shadow = () => ({ type: "outer", color: "0B1F33", blur: 7, offset: 2, angle: 45, opacity: 0.14 });

/* 内容页骨架：浅色底 + 左上角小签 + 标题 */
function contentSlide(kicker, title) {
  const s = pres.addSlide();
  s.background = { color: P.LIGHT };
  s.addText(kicker, { x: M, y: 0.34, w: 9, h: 0.3, fontSize: 12, fontFace: F, color: P.ACCENT, charSpacing: 3, margin: 0 });
  s.addText(title, { x: M, y: 0.62, w: W - 2 * M, h: 0.72, fontSize: 30, fontFace: F, bold: true, color: P.TEXT, margin: 0 });
  s.addText("知盾 ZhìDùn", { x: W - 2.1, y: 0.38, w: 1.55, h: 0.28, fontSize: 11, fontFace: F, color: P.MUTED, align: "right", margin: 0 });
  return s;
}
function pageNum(s, n) {
  s.addText(String(n).padStart(2, "0"), { x: W - 1.05, y: H - 0.52, w: 0.5, h: 0.3, fontSize: 11, fontFace: F, color: P.MUTED, align: "right", margin: 0 });
}

/* ---------- 1 封面 ---------- */
{
  const s = pres.addSlide();
  s.background = { color: P.DARK };
  // 同心圆轨道装饰（呼应 Web 控制台 hero）
  const rings = [[9.2, 1.15, 3.9], [10.05, 2.0, 2.2], [10.7, 2.65, 0.9]];
  rings.forEach(([x, y, d], i) => s.addShape(pres.shapes.OVAL, {
    x, y, w: d, h: d, fill: { color: P.DARK, transparency: 100 },
    line: { color: i === 2 ? P.ACCENT : P.DARK2, width: i === 2 ? 1.5 : 1.2 },
  }));
  s.addShape(pres.shapes.OVAL, { x: 11.0, y: 2.95, w: 0.3, h: 0.3, fill: { color: P.ACCENT } });
  s.addText("ZHIDUN AI SECURITY INTELLIGENCE", { x: M, y: 2.02, w: 9, h: 0.34, fontSize: 13, fontFace: F, color: P.ACCENT, charSpacing: 4, margin: 0 });
  s.addText("智能体驱动的 AI 安全知识情报系统", { x: M, y: 2.42, w: 10.6, h: 0.95, fontSize: 40, fontFace: F, bold: true, color: "FFFFFF", margin: 0 });
  s.addText("多源监测 · 证据富化 · 可追溯问答的 AI 安全情报闭环", { x: M, y: 3.42, w: 10, h: 0.45, fontSize: 18, fontFace: F, color: P.ON_DARK_MUTED, margin: 0 });
  const meta = [
    ["参赛赛题", "赛题九 · 网信产业应用赛道"],
    ["命题单位", "奇安信科技集团股份有限公司"],
    ["赛事", "第三届\u201c中国电子杯\u201d高校 ICT 产教融合创新大赛 · 校内初赛"],
  ];
  meta.forEach(([k, v], i) => {
    s.addText(k, { x: M, y: 4.62 + i * 0.44, w: 1.35, h: 0.36, fontSize: 13, fontFace: F, bold: true, color: P.ACCENT, margin: 0 });
    s.addText(v, { x: M + 1.5, y: 4.62 + i * 0.44, w: 9.5, h: 0.36, fontSize: 13, fontFace: F, color: P.ON_DARK, margin: 0 });
  });
  s.addText("证据先于结论 · 每条情报可回溯原始出处", { x: M, y: H - 0.78, w: 8, h: 0.35, fontSize: 12, fontFace: F, italic: true, color: P.ON_DARK_MUTED, margin: 0 });
}

/* ---------- 2 问题与定位 ---------- */
{
  const s = contentSlide("PROBLEM & POSITIONING", "AI 安全情报的三重困境与我们的答案");
  const pains = [
    ["信息过载", "漏洞散落在 CVE/NVD、社区、厂商公告、论文、博客，人工跟踪不可持续"],
    ["覆盖缺失", "传统情报系统面向通用漏洞，对 AI 框架、模型层、智能体风险缺乏深度覆盖"],
    ["决策断层", "缺少自然语言问答与证据链，难以支撑\u201c影响哪些资产、如何处置\u201d的应急决策"],
  ];
  pains.forEach(([t, d], i) => {
    const x = M + i * 4.18;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.72, w: 3.9, h: 1.72, rectRadius: 0.08, fill: { color: P.PANEL2 }, line: { color: "D9E4EF", width: 0.75 }, shadow: shadow() });
    s.addText(t, { x: x + 0.28, y: 1.94, w: 3.3, h: 0.4, fontSize: 17, fontFace: F, bold: true, color: P.PRIMARY, margin: 0 });
    s.addText(d, { x: x + 0.28, y: 2.38, w: 3.36, h: 0.95, fontSize: 12.5, fontFace: F, color: P.MUTED, margin: 0, lineSpacingMultiple: 1.15 });
  });
  s.addText("知盾将分散情报组织成可审计知识库，以带来源的问答支持处置；证据不足时明确拒答。",
    { x: M, y: 3.86, w: W - 2 * M, h: 0.75, fontSize: 15.5, fontFace: F, color: P.TEXT, margin: 0, breakLine: false });
  // 三步闭环
  const steps = [["持续发现", "多源自动监测"], ["可信富化", "证据化关联加工"], ["可追溯问答", "引用+推理链+拒答"]];
  steps.forEach(([t, d], i) => {
    const x = M + i * 4.18;
    s.addShape(pres.shapes.OVAL, { x: x + 0.1, y: 4.95, w: 0.52, h: 0.52, fill: { color: P.PRIMARY } });
    s.addText(String(i + 1), { x: x + 0.1, y: 4.95, w: 0.52, h: 0.52, fontSize: 18, fontFace: F, bold: true, color: "FFFFFF", align: "center", valign: "middle", margin: 0 });
    s.addText(t, { x: x + 0.78, y: 4.93, w: 2.9, h: 0.34, fontSize: 15.5, fontFace: F, bold: true, color: P.TEXT, margin: 0 });
    s.addText(d, { x: x + 0.78, y: 5.27, w: 3.0, h: 0.3, fontSize: 12, fontFace: F, color: P.MUTED, margin: 0 });
    if (i < 2) s.addText("→", { x: x + 3.72, y: 4.98, w: 0.4, h: 0.45, fontSize: 20, fontFace: F, color: P.ACCENT, margin: 0 });
  });
  pageNum(s, 2);
}

/* ---------- 3 总体架构 ---------- */
{
  const s = contentSlide("SYSTEM ARCHITECTURE", "总体架构：六层流水线 + 全程审计");
  s.addImage({ path: path.join(__dirname, "fig1_architecture.png"), x: 0.72, y: 1.62, w: 8.35, h: 5.44 });
  const notes = [
    ["零依赖内核", "Python 标准库 + SQLite/FTS5，断网无 Key 可完整演示"],
    ["单一事实源", "文档与证据化声明分离存储，双时间戳+采集模式"],
    ["受控增强", "可选 GLM-5.3 规划问题并选择公开证据段落；失败回退"],
    ["工程基础", "REST API / 指标 / Docker / CI 配置；运行记录待补"],
  ];
  notes.forEach(([t, d], i) => {
    const y = 1.72 + i * 1.32;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 9.42, y, w: 3.36, h: 1.16, rectRadius: 0.06, fill: { color: i % 2 ? P.PANEL2 : P.PANEL }, line: { color: "D9E4EF", width: 0.75 } });
    s.addText(t, { x: 9.66, y: y + 0.12, w: 2.9, h: 0.34, fontSize: 14.5, fontFace: F, bold: true, color: P.PRIMARY, margin: 0 });
    s.addText(d, { x: 9.66, y: y + 0.46, w: 2.94, h: 0.62, fontSize: 11.5, fontFace: F, color: P.MUTED, margin: 0, lineSpacingMultiple: 1.1 });
  });
  pageNum(s, 3);
}

/* ---------- 4 智能体编排 ---------- */
{
  const s = contentSlide("MULTI-AGENT ORCHESTRATION", "10 类角色事件：规则编排、失败留痕");
  s.addImage({ path: path.join(__dirname, "fig2_agent_flow.png"), x: 0.62, y: 1.66, w: 8.0, h: 4.91 });
  const roles = ["调度代理", "监测代理", "自愈代理", "分诊代理", "核验代理", "归一索引代理", "富化代理", "关联推理代理", "问答规划代理", "问答核验代理"];
  roles.forEach((r, i) => {
    const y = 1.66 + Math.floor(i / 2) * 0.62;
    const x = 8.95 + (i % 2) * 2.0;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: 1.88, h: 0.5, rectRadius: 0.05, fill: { color: P.PANEL }, line: { color: "C9D9E8", width: 0.75 } });
    s.addText(r, { x, y, w: 1.88, h: 0.5, fontSize: 11.5, fontFace: F, bold: true, color: P.PRIMARY, align: "center", valign: "middle", margin: 0 });
  });
  s.addText("角色名称标识确定性代码步骤；标签数量不等于独立自主 Agent 数。GLM-5.3 仅规划意图并选择本地公开证据段落。", { x: 8.95, y: 4.86, w: 3.85, h: 1.3, fontSize: 12, fontFace: F, color: P.MUTED, margin: 0, lineSpacingMultiple: 1.25 });
  pageNum(s, 4);
}

/* ---------- 5 监测模块 ---------- */
{
  const s = contentSlide("MODULE 1 · MONITORING", "12 个在线配置：9 个监测候选 + 3 个知识源");
  const rows = [
    ["官方漏洞库", "NVD CVE API 2.0（支持 API Key）"],
    ["开源公告库", "GitHub Advisory + OSV.dev（来源可重叠）"],
    ["政府已利用目录", "CISA KEV Feed（置信度 0.98）"],
    ["厂商博客候选", "HuggingFace 通用博客经关键词过滤"],
    ["CERT 公告", "CISA 网络安全通告"],
    ["安全社区媒体", "BleepingComputer + 安全客 RSS"],
    ["研究博客", "NIST Cybersecurity Insights"],
    ["知识底座", "arXiv 论文 · NIST 标准新闻 · 网信办政策"],
  ];
  rows.forEach(([k, v], i) => {
    const y = 1.66 + i * 0.52;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: M, y, w: 2.35, h: 0.44, rectRadius: 0.05, fill: { color: i === 7 ? P.PRIMARY : P.PANEL } });
    s.addText(k, { x: M + 0.14, y, w: 2.1, h: 0.44, fontSize: 12, fontFace: F, bold: true, color: i === 7 ? "FFFFFF" : P.PRIMARY, valign: "middle", margin: 0 });
    s.addText(v, { x: M + 2.6, y, w: 4.6, h: 0.44, fontSize: 12.5, fontFace: F, color: P.TEXT, valign: "middle", margin: 0 });
  });
  const feats = [
    ["增量游标 + 10 分钟重叠窗口", "容忍乱序发布；入库幂等保证重叠不产生重复实体"],
    ["内容哈希双级去重", "同源变更原位更新；跨源同 CVE 自动归并"],
    ["时效度量内建", "双时间戳 + demo/live 模式标记，P50/P95 延迟经 /metrics 暴露"],
    ["失败自愈", "指数退避重试 3 次 → 源隔离 + 健康度跟踪"],
  ];
  feats.forEach(([t, d], i) => {
    const y = 1.66 + i * 1.18;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 8.1, y, w: 4.68, h: 1.02, rectRadius: 0.06, fill: { color: P.PANEL2 }, line: { color: "D9E4EF", width: 0.75 } });
    s.addText(t, { x: 8.34, y: y + 0.1, w: 4.2, h: 0.32, fontSize: 13.5, fontFace: F, bold: true, color: P.PRIMARY, margin: 0 });
    s.addText(d, { x: 8.34, y: y + 0.44, w: 4.24, h: 0.5, fontSize: 11, fontFace: F, color: P.MUTED, margin: 0 });
  });
  s.addText("注：一次全源运行 10/12 任务成功、入库 442 篇；2 源 HTTP 403。7 类独立来源与 ≤6h 延迟仍待持续验证。", { x: M, y: 5.95, w: 11.8, h: 0.4, fontSize: 10.5, fontFace: F, italic: true, color: P.MUTED, margin: 0 });
  pageNum(s, 5);
}

/* ---------- 6 富化模块 ---------- */
{
  const s = contentSlide("MODULE 2 · ENRICHMENT", "来源字段抽取与规则富化");
  const dims = [
    ["受影响产品与版本", "来源字段映射 + 区间规范化"],
    ["CVSS 与风险级别", "数值校验，缺失标\u201c待评估\u201d不记 0 分"],
    ["修复版本与补丁链接", "fixed 字段 + patch 标签参考"],
    ["PoC 候选链接", "离线样例无此项；在线只收录元数据"],
    ["相关论文/分析", "显式提及或同产品规则关联"],
    ["受影响资产匹配", "授权清单 × 保守版本区间"],
    ["处置优先级", "CVSS × 暴露系数 × 关键度"],
  ];
  dims.forEach(([t, d], i) => {
    const y = 1.62 + i * 0.66;
    s.addShape(pres.shapes.OVAL, { x: M, y: y + 0.05, w: 0.44, h: 0.44, fill: { color: i === 6 ? P.ACCENT : P.PRIMARY } });
    s.addText(String(i + 1), { x: M, y: y + 0.05, w: 0.44, h: 0.44, fontSize: 14, fontFace: F, bold: true, color: "FFFFFF", align: "center", valign: "middle", margin: 0 });
    s.addText(t, { x: M + 0.62, y, w: 2.95, h: 0.54, fontSize: 13.5, fontFace: F, bold: true, color: P.TEXT, valign: "middle", margin: 0 });
    s.addText(d, { x: 4.25, y, w: 3.1, h: 0.54, fontSize: 11.5, fontFace: F, color: P.MUTED, valign: "middle", margin: 0 });
  });
  // claims 证据模型面板
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 7.75, y: 1.62, w: 5.05, h: 4.05, rectRadius: 0.08, fill: { color: P.DARK }, shadow: shadow() });
  s.addText("claims 证据化声明模型", { x: 8.05, y: 1.86, w: 4.4, h: 0.4, fontSize: 16, fontFace: F, bold: true, color: "FFFFFF", margin: 0 });
  s.addText("(subject, predicate, object)", { x: 8.05, y: 2.26, w: 4.4, h: 0.32, fontSize: 12.5, fontFace: "Menlo", color: P.ACCENT, margin: 0 });
  s.addText([
    { text: "document_id → 挂接来源文档（外键）", options: { bullet: bu(), breakLine: true, color: P.ON_DARK } },
    { text: "evidence → 文档摘要摘录，非逐字段原文", options: { bullet: bu(), breakLine: true, color: P.ON_DARK } },
    { text: "confidence → 按来源类别分层（KEV 0.98 … 博客 0.62）", options: { bullet: bu(), breakLine: true, color: P.ON_DARK } },
    { text: "间接证据自动降权（PoC 链接 −0.12）", options: { bullet: bu(), color: P.ON_DARK } },
  ], { x: 8.05, y: 2.7, w: 4.5, h: 1.9, fontSize: 12.5, fontFace: F, paraSpaceAfter: 10, margin: 0 });
  s.addText("5 维深度富化和准确率仍待独立真值评测", { x: 8.05, y: 4.9, w: 4.5, h: 0.55, fontSize: 13, fontFace: F, bold: true, italic: true, color: P.ACCENT, margin: 0 });
  pageNum(s, 6);
}

/* ---------- 7 关联推理 ---------- */
{
  const s = contentSlide("AUTOMATIC ASSOCIATION", "三类规则关联：保留关系来源与理由");
  const tiers = [
    ["①", "同 CVE 跨源归并", "GitHub 公告 + Wiz 研究 → 同一漏洞证据组，多源分歧并列呈现，不由模型静默裁决", "强"],
    ["②", "mentioned_in 显式提及", "论文/综述正文提及某 CVE 即建立反向关联边；问答与详情页据此给出\u201c哪些研究讨论了它\u201d", "中"],
    ["③", "产品重合推断", "文档未点名 CVE 但涉及同产品 → 标注为弱关联并明示\u201c文档未直接提及该漏洞标识\u201d", "弱"],
  ];
  tiers.forEach(([n, t, d, tag], i) => {
    const y = 1.72 + i * 1.5;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: M, y, w: 11.9, h: 1.3, rectRadius: 0.07, fill: { color: i === 0 ? P.PANEL : P.PANEL2 }, line: { color: "D9E4EF", width: 0.75 }, shadow: shadow() });
    s.addText(n, { x: M + 0.3, y: y + 0.3, w: 0.7, h: 0.7, fontSize: 30, fontFace: F, bold: true, color: P.ACCENT, margin: 0 });
    s.addText(t, { x: M + 1.15, y: y + 0.16, w: 3.6, h: 0.42, fontSize: 16.5, fontFace: F, bold: true, color: P.TEXT, margin: 0 });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: M + 1.15, y: y + 0.66, w: 0.85, h: 0.36, rectRadius: 0.18, fill: { color: tag === "强" ? P.GOOD : tag === "中" ? P.ACCENT : P.WARN } });
    s.addText(tag + "关联", { x: M + 1.15, y: y + 0.66, w: 0.85, h: 0.36, fontSize: 10.5, fontFace: F, bold: true, color: "FFFFFF", align: "center", valign: "middle", margin: 0 });
    s.addText(d, { x: M + 4.6, y: y + 0.18, w: 6.9, h: 0.98, fontSize: 12.5, fontFace: F, color: P.MUTED, valign: "middle", margin: 0, lineSpacingMultiple: 1.2 });
  });
  s.addText("每条关联边在使用时输出关联理由与出处——\u201c相关\u201d不是黑盒，而是可检查的证据路径。", { x: M, y: 6.35, w: 11.9, h: 0.4, fontSize: 13.5, fontFace: F, bold: true, color: P.PRIMARY, margin: 0 });
  pageNum(s, 7);
}

/* ---------- 8 问答模块 ---------- */
{
  const s = contentSlide("MODULE 3 · GROUNDED QA", "规则问答：来源引用、关系路径与拒答");
  s.addImage({ path: path.join(__dirname, "fig3_qa_flow.png"), x: 0.62, y: 1.66, w: 7.6, h: 4.24 });
  s.addText("当前可检查的规则路径", { x: 8.5, y: 1.7, w: 4.2, h: 0.36, fontSize: 15, fontFace: F, bold: true, color: P.TEXT, margin: 0 });
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 8.5, y: 2.12, w: 4.28, h: 2.5, rectRadius: 0.06, fill: { color: P.PANEL2 }, line: { color: "D9E4EF", width: 0.75 } });
  s.addText([
    { text: "问：CVE-2024-37032 影响哪些资产、如何修复？", options: { bold: true, color: P.PRIMARY, breakLine: true } },
    { text: "trace:", options: { fontFace: "Menlo", color: P.ACCENT, breakLine: true } },
    { text: "CVE → affects_product → ollama [1][2]", options: { fontFace: "Menlo", color: P.TEXT, breakLine: true } },
    { text: "CVE → local_asset_version_match", options: { fontFace: "Menlo", color: P.TEXT, breakLine: true } },
    { text: "   → 演示-虚构-Ollama节点", options: { fontFace: "Menlo", color: P.TEXT, breakLine: true } },
    { text: "证据：公告版本范围 + 本地授权清单", options: { fontFace: "Menlo", color: P.MUTED } },
  ], { x: 8.74, y: 2.3, w: 3.9, h: 2.2, fontSize: 11.5, fontFace: F, paraSpaceAfter: 7, margin: 0 });
  const chips = [["多轮上下文", "省略主语追问"], ["显式拒答", "abstained + 缺失说明"], ["可选 GLM", "意图+证据选择，失败回退"]];
  chips.forEach(([t, d], i) => {
    const x = 8.5 + i * 1.46;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 4.86, w: 1.36, h: 1.0, rectRadius: 0.06, fill: { color: P.PANEL } });
    s.addText(t, { x: x + 0.08, y: 4.96, w: 1.2, h: 0.3, fontSize: 10.5, fontFace: F, bold: true, color: P.PRIMARY, align: "center", margin: 0 });
    s.addText(d, { x: x + 0.08, y: 5.28, w: 1.22, h: 0.52, fontSize: 9, fontFace: F, color: P.MUTED, align: "center", margin: 0 });
  });
  pageNum(s, 8);
}

/* ---------- 9 安全边界 ---------- */
{
  const s = contentSlide("SECURITY & TRUST BOUNDARY", "安全边界：把不可控性锁进最小范围");
  const rows = [
    ["不可信输入处理", "网页按数据处理；GLM 接收问题与候选公开情报段落，不接收资产段落或数据库全文"],
    ["注入与 Web 防线", "严格 CSP · 跨源写入校验 · 1MB 请求上限 · 路径穿越防护"],
    ["授权资产原则", "只比对本地登记清单，不扫描、不探测任何陌生目标"],
    ["PoC 只读不执行", "仅收录元数据与链接，答案明示\u201c系统不会执行验证代码\u201d"],
    ["拒答设计", "实体不存在/证据不足 → abstained=true + 说明缺失，与引用核验一起纳入评测"],
  ];
  rows.forEach(([t, d], i) => {
    const y = 1.66 + i * 0.86;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: M, y, w: 2.9, h: 0.72, rectRadius: 0.06, fill: { color: P.PRIMARY } });
    s.addText(t, { x: M + 0.18, y, w: 2.6, h: 0.72, fontSize: 13, fontFace: F, bold: true, color: "FFFFFF", valign: "middle", margin: 0 });
    s.addText(d, { x: M + 3.15, y, w: 9.0, h: 0.72, fontSize: 12.5, fontFace: F, color: P.TEXT, valign: "middle", margin: 0, lineSpacingMultiple: 1.12 });
  });
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: M, y: 6.02, w: 12.23, h: 0.92, rectRadius: 0.07, fill: { color: P.DARK } });
  s.addText([
    { text: "自定 Agentic AI 安全样例 · 6/6 通过", options: { bold: true, color: "FFFFFF", breakLine: true } },
    { text: "参考 OWASP 建议作六攻击面映射；本地样例通过不等于外部认证或全面安全保证", options: { color: "9FB6CC", fontSize: 11 } },
  ], { x: M + 0.3, y: 6.12, w: 11.6, h: 0.75, fontSize: 14, fontFace: F, margin: 0 });
  pageNum(s, 9);
}

/* ---------- 10 工程化 ---------- */
{
  const s = contentSlide("ENGINEERING", "工程基础：本地启动、接口与部署配置");
  const cards = [
    ["一键启动", "python3 -m app.server\n零第三方依赖 · 断网可演示", "终端"],
    ["REST API", "问答/采集/详情/指标接口\n请求校验与安全响应头", "接口"],
    ["可观测", "运行与事件轨迹界面化\nPrometheus /metrics 指标", "监控"],
    ["容器化", "Dockerfile 非 root 运行\nCompose 健康检查+命名卷", "部署"],
    ["CI 回归", "GitHub Actions 配置单测\n远端运行状态需另行核验", "质量"],
    ["CLI 与评测", "cli.py 演示/统计/采集\nevaluate.py 开发规则自测", "验收"],
  ];
  cards.forEach(([t, d, tag], i) => {
    const x = M + (i % 3) * 4.18, y = 1.72 + Math.floor(i / 3) * 2.3;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: 3.9, h: 2.05, rectRadius: 0.08, fill: { color: P.PANEL2 }, line: { color: "D9E4EF", width: 0.75 }, shadow: shadow() });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: x + 2.9, y: y + 0.22, w: 0.78, h: 0.34, rectRadius: 0.17, fill: { color: P.PANEL } });
    s.addText(tag, { x: x + 2.9, y: y + 0.22, w: 0.78, h: 0.34, fontSize: 10, fontFace: F, color: P.PRIMARY, align: "center", valign: "middle", margin: 0 });
    s.addText(t, { x: x + 0.26, y: y + 0.2, w: 2.6, h: 0.42, fontSize: 16.5, fontFace: F, bold: true, color: P.TEXT, margin: 0 });
    s.addText(d, { x: x + 0.26, y: y + 0.72, w: 3.4, h: 1.1, fontSize: 12, fontFace: F, color: P.MUTED, margin: 0, lineSpacingMultiple: 1.25 });
  });
  pageNum(s, 10);
}

/* ---------- 11 实测结果 ---------- */
{
  const s = contentSlide("EVALUATION RESULTS", "离线开发规则自测：9/9 通过");
  const stats = [
    ["9/9", "固定规则通过", "基础5 + 同CVE关联3 + 拒答1"],
    ["11/11", "必需引用存在", "来源 ID 和 URL 与样例匹配"],
    ["14/14", "事实同行标记", "不能代替来源内容核验"],
    ["7/7", "原样重放跳过", "不代表在线去重准确率"],
  ];
  stats.forEach(([n, t, d], i) => {
    const x = M + i * 3.13;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.66, w: 2.9, h: 1.95, rectRadius: 0.08, fill: { color: i === 0 ? P.DARK : P.PANEL2 }, line: { color: "D9E4EF", width: 0.75 }, shadow: shadow() });
    s.addText(n, { x: x + 0.2, y: 1.82, w: 2.5, h: 0.85, fontSize: 40, fontFace: F, bold: true, color: i === 0 ? P.ACCENT : P.PRIMARY, margin: 0 });
    s.addText(t, { x: x + 0.2, y: 2.7, w: 2.5, h: 0.32, fontSize: 13.5, fontFace: F, bold: true, color: i === 0 ? "FFFFFF" : P.TEXT, margin: 0 });
    s.addText(d, { x: x + 0.2, y: 3.02, w: 2.55, h: 0.5, fontSize: 10.5, fontFace: F, color: i === 0 ? P.ON_DARK_MUTED : P.MUTED, margin: 0 });
  });
  const tableRows = [
    [{ text: "评测项", options: { bold: true, color: "FFFFFF", fill: { color: P.PRIMARY } } },
     { text: "结果", options: { bold: true, color: "FFFFFF", fill: { color: P.PRIMARY } } },
     { text: "口径说明", options: { bold: true, color: "FFFFFF", fill: { color: P.PRIMARY } } }],
    ["单元测试", "62/62 通过", "连接器/归一去重/版本区间/拒答/Agentic 自安全；2026-09-29 本地回归"],
    ["漏洞实体归并", "3 实体 / 7 文档", "同 CVE 双来源正确归并为证据组"],
    ["资产匹配", "3/3 符合预期", "affected×2、not_affected×1，含区间边界用例"],
    ["问答响应分布", "以现场运行为准", "单用户进程内 ask；无 HTTP/联网/模型，不能证明 ≤5s 档"],
  ];
  s.addTable(tableRows, {
    x: M, y: 3.95, w: W - 2 * M, colW: [2.6, 3.2, 6.48],
    fontSize: 12, fontFace: F, color: P.TEXT, valign: "middle", align: "left",
    border: { pt: 0.75, color: "D9E4EF" }, fill: { color: "FFFFFF" },
    rowH: 0.42, margin: 0.08,
  });
  s.addText("口径：题目与 7 条人工摘要同源；9/9 是规则通过率，不是语义准确率、富化召回率或官方评分。", { x: M, y: 6.42, w: 12.2, h: 0.32, fontSize: 10.5, fontFace: F, italic: true, color: P.MUTED, margin: 0 });
  pageNum(s, 11);
}

/* ---------- 12 创新点 ---------- */
{
  const s = contentSlide("INNOVATIONS", "设计特色与当前验证边界");
  const items = [
    ["证据化声明模型", "富化重构为带出处、带证据片段、带置信度的 claims 三元组；多源分歧并列而非静默裁决"],
    ["三类规则关联", "同 CVE 归并 / mentioned_in 提及 / 产品重合推断，关联理由随答案输出"],
    ["拒答作为一等能力", "abstained + 缺失说明纳入评测题集，直接对抗情报系统幻觉风险"],
    ["受控 GLM-5.3 增强", "意图规划和公开证据段落选择；失败回退。一条真实 HTTP 问答已走通"],
    ["自安全+可审计编排", "OWASP 六攻击面自检为产品功能；10 类 Agent 每步决策落盘，自愈回路留痕"],
    ["指标诚实工程", "双时间戳+模式标记延迟统计、快照/在线三态区分，每项声明可复核"],
  ];
  items.forEach(([t, d], i) => {
    const x = M + (i % 2) * 6.2, y = 1.66 + Math.floor(i / 2) * 1.62;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: 5.9, h: 1.42, rectRadius: 0.07, fill: { color: i % 2 ? P.PANEL2 : P.PANEL }, line: { color: "D9E4EF", width: 0.75 } });
    s.addText(String(i + 1).padStart(2, "0"), { x: x + 0.22, y: y + 0.16, w: 0.8, h: 0.55, fontSize: 24, fontFace: F, bold: true, color: P.ACCENT, margin: 0 });
    s.addText(t, { x: x + 1.0, y: y + 0.16, w: 4.7, h: 0.36, fontSize: 14.5, fontFace: F, bold: true, color: P.TEXT, margin: 0 });
    s.addText(d, { x: x + 1.0, y: y + 0.56, w: 4.72, h: 0.75, fontSize: 11.5, fontFace: F, color: P.MUTED, margin: 0, lineSpacingMultiple: 1.15 });
  });
  s.addText("该原型把公开来源、人工整理摘要、本地资产版本匹配与带出处问答放在一套可离线复现的系统中。", { x: M, y: 6.6, w: 12.2, h: 0.35, fontSize: 12, fontFace: F, color: P.PRIMARY, margin: 0 });
  pageNum(s, 12);
}

/* ---------- 13 边界与路线 ---------- */
{
  const s = contentSlide("HONEST BOUNDARIES & ROADMAP", "如实标注的边界与可执行路线");
  const bounds = [
    ["在线持续运行实测", "逐类源成功率与 ≤6h 延迟分布；归档原始批次"],
    ["富化真值评测集", "分维度 TP/FP/FN 人工标注、双人复核 → 准确率/召回率"],
    ["语义检索增强", "本地嵌入模型向量召回 + FTS5 混合排序；题集扩至 50+ 并分离留出集"],
    ["GLM-5.3 效果对照", "扩展当前单条 HTTP 验收，用留出题集比较质量和延迟"],
  ];
  s.addText("当前如实未声称的", { x: M, y: 1.6, w: 5, h: 0.4, fontSize: 16, fontFace: F, bold: true, color: P.WARN, margin: 0 });
  s.addText([
    { text: "线上 ≥7 类源持续可用性与 ≤6h 采集延迟", options: { bullet: bu(), breakLine: true } },
    { text: "富化准确率/召回率 ≥95% 的人工真值评测", options: { bullet: bu(), breakLine: true } },
    { text: "大规模题集语义泛化与多跳准确率", options: { bullet: bu(), breakLine: true } },
    { text: "生产级高并发、完整 DevOps 实测", options: { bullet: bu() } },
  ], { x: M, y: 2.1, w: 5.4, h: 2.2, fontSize: 13.5, fontFace: F, color: P.TEXT, paraSpaceAfter: 12, margin: 0 });
  s.addText("验收路线", { x: 6.6, y: 1.6, w: 5, h: 0.4, fontSize: 16, fontFace: F, bold: true, color: P.GOOD, margin: 0 });
  bounds.forEach(([t, d], i) => {
    const y = 2.1 + i * 1.06;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 6.6, y, w: 6.15, h: 0.92, rectRadius: 0.06, fill: { color: P.PANEL2 }, line: { color: "D9E4EF", width: 0.75 } });
    s.addText(t, { x: 6.84, y: y + 0.1, w: 5.7, h: 0.34, fontSize: 13, fontFace: F, bold: true, color: P.PRIMARY, margin: 0 });
    s.addText(d, { x: 6.84, y: y + 0.46, w: 5.72, h: 0.4, fontSize: 11, fontFace: F, color: P.MUTED, margin: 0 });
  });
  s.addText("下一步先归档在线原始记录，再建立独立人工真值集，按赛题档位复测。", { x: M, y: 6.5, w: 12.2, h: 0.42, fontSize: 13, fontFace: F, italic: true, bold: true, color: P.PRIMARY, margin: 0 });
  pageNum(s, 13);
}

/* ---------- 14 结尾 ---------- */
{
  const s = pres.addSlide();
  s.background = { color: P.DARK };
  s.addShape(pres.shapes.OVAL, { x: 1.05, y: 2.5, w: 3.4, h: 3.4, fill: { color: P.DARK, transparency: 100 }, line: { color: P.DARK2, width: 1.2 } });
  s.addShape(pres.shapes.OVAL, { x: 1.85, y: 3.3, w: 1.8, h: 1.8, fill: { color: P.DARK, transparency: 100 }, line: { color: P.DARK2, width: 1.2 } });
  s.addShape(pres.shapes.OVAL, { x: 2.42, y: 3.87, w: 0.66, h: 0.66, fill: { color: P.ACCENT } });
  s.addText("让每条安全情报", { x: 5.3, y: 2.55, w: 7.4, h: 0.75, fontSize: 34, fontFace: F, bold: true, color: "FFFFFF", margin: 0 });
  s.addText("有来源、有关联、有答案。", { x: 5.3, y: 3.3, w: 7.4, h: 0.75, fontSize: 34, fontFace: F, bold: true, color: P.ACCENT, margin: 0 });
  s.addText("现场演示：python3 -m app.server --no-scheduler  →  http://127.0.0.1:8765", { x: 5.3, y: 4.45, w: 7.5, h: 0.4, fontSize: 14, fontFace: F, color: P.ON_DARK_MUTED, margin: 0 });
  s.addText("知盾 ZhìDùn · 赛题九 网信产业应用赛道 · 第三届\u201c中国电子杯\u201d", { x: 5.3, y: 5.0, w: 7.5, h: 0.36, fontSize: 12, fontFace: F, color: P.ON_DARK_MUTED, margin: 0 });
}

pres.writeFile({ fileName: path.join(__dirname, "知盾AI安全知识情报系统讲解PPT.pptx") }).then(() => console.log("PPTX written"));
