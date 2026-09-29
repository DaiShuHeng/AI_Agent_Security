"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
const state = {
  page: "overview", dashboard: null, vulnerabilities: [], documents: [], assets: [], runs: [],
  sessionId: null, collecting: false, asking: false, detailRequest: 0, documentRequest: 0,
  detailReturnFocus: null, selfcheckPending: false, questionRequest: 0,
  loaded: { dashboard: false, vulnerabilities: false, knowledge: false, assets: false, runs: false, modelHealth: false },
};
const pageMeta = {
  overview: ["总览仪表盘", "MISSION CONTROL / 01"],
  vulnerabilities: ["漏洞情报", "INTELLIGENCE / 02"],
  knowledge: ["知识底座", "EVIDENCE LIBRARY / 03"],
  assistant: ["Agent 问答", "REASONING AGENT / 04"],
  sources: ["数据源状态", "COLLECTION NETWORK / 05"],
  assets: ["授权资产", "ASSET INVENTORY / 06"],
  runs: ["运行与轨迹", "OPERATIONS / 07"],
};
const kindNames = { vulnerability: "漏洞情报", paper: "研究论文", standard: "技术标准", policy: "政策法规", article: "分析文章", advisory: "安全公告", blog: "研究博客", poc: "PoC 元数据" };
const categoryNames = { official_vulnerability: "官方漏洞库", cve: "官方漏洞库", nvd: "NVD 漏洞库", github_advisories: "开源安全公告", cisa_kev: "已利用漏洞目录", community: "安全社区", vendor: "厂商公告", blog: "研究博客", paper: "研究论文", standard: "技术标准", policy: "政策法规", cert: "CERT 公告", kev: "已利用漏洞目录", osv: "开源安全公告", github: "GitHub 安全公告", knowledge: "知识来源" };
const predicateNames = { affects_product: "影响产品", affected_version: "受影响版本", fixed_version: "修复版本", cvss: "CVSS 评分", severity: "风险等级", epss: "EPSS 利用可能性", poc_reference: "PoC 参考", patch_reference: "修复参考", reference: "参考链接", alias: "别名", known_exploited: "已知被利用", mentioned_in: "提及于", relates_to: "关联对象", related_paper: "相关论文", related_article: "相关分析", related_standard: "相关标准", related_policy: "相关政策" };
const sourceStatusNames = { healthy: "正常", error: "异常", idle: "待运行", demo: "离线快照", disabled: "已禁用" };
const exposureNames = { internet: "互联网", internal: "内部网络", isolated: "隔离环境" };
const impactNames = { affected: "可能受影响", not_affected: "未匹配影响版本", unknown: "待核验" };
const DOCUMENT_LIMIT = 200;

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined && value !== null) node.textContent = String(value);
  return node;
}
function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}
function append(parent, ...children) { children.forEach(child => { if (child !== null && child !== undefined) parent.append(child); }); return parent; }
function list(value) { return Array.isArray(value) ? value : []; }
function pick(...values) { return values.find(value => value !== null && value !== undefined && String(value).trim() !== "") ?? ""; }
function number(value) { const parsed = Number(value); return Number.isFinite(parsed) ? parsed : 0; }
function count(value) { return number(value).toLocaleString("zh-CN"); }
function truncate(value, limit = 120) { const s = String(value || ""); return s.length > limit ? s.slice(0, limit) + "…" : s; }
function cleanStatus(value, allowed, fallback) { const key = String(value || "").toLowerCase(); return allowed.includes(key) ? key : fallback; }
function severityOf(item) {
  const raw = String(item.severity || "").toLowerCase();
  if (["critical", "严重"].includes(raw)) return "critical";
  if (["high", "高", "高危"].includes(raw)) return "high";
  if (["medium", "moderate", "中", "中危"].includes(raw)) return "medium";
  if (["low", "低", "低危"].includes(raw)) return "low";
  const cvss = Number(item.cvss);
  if (!Number.isFinite(cvss) || item.cvss === null || item.cvss === "") return "unknown";
  return cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low";
}
function severityLabel(code) { return ({critical:"严重", high:"高危", medium:"中危", low:"低危", unknown:"未评级"})[code] || "未评级"; }
function severityBadge(item) { const code = severityOf(item); return element("span", `severity ${code}`, severityLabel(code)); }
function formatDate(value, includeTime = false) {
  if (!value) return "暂无记录";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value).slice(0, 19);
  return new Intl.DateTimeFormat("zh-CN", { timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit", day: "2-digit", ...(includeTime ? {hour:"2-digit",minute:"2-digit",hour12:false} : {}) }).format(date);
}
function formatRelative(value) {
  if (!value) return "尚未运行";
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return formatDate(value, true);
  const delta = Math.max(0, Date.now() - timestamp);
  if (delta < 60_000) return "刚刚";
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)} 分钟前`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)} 小时前`;
  return formatDate(value);
}
function safeURL(value) {
  try { const url = new URL(String(value)); return url.protocol === "https:" ? url.href : null; }
  catch { return null; }
}
function externalLink(url, label = "查看来源") {
  const href = safeURL(url);
  if (!href) return element("span", "external-unavailable", label === "查看来源" ? "来源链接不可用" : label);
  const anchor = element("a", "", label);
  anchor.href = href; anchor.target = "_blank"; anchor.rel = "noopener noreferrer";
  return anchor;
}
function empty(container, message, className = "empty-inline") { container.replaceChildren(element("div", className, message)); }
function toast(message, type = "info") {
  const box = element("div", `toast ${type}`, message);
  $("#toastRegion").append(box);
  window.setTimeout(() => box.remove(), 5200);
}
function serviceStatus(connected) {
  const badge = $("#serviceStatus");
  badge.classList.toggle("error", !connected);
  $("#serviceStatusText").textContent = connected ? "本地服务已连接" : "服务连接失败";
}
async function loadModelHealth(force = false) {
  if (state.loaded.modelHealth && !force) return;
  const badge = $("#modelAvailability");
  try {
    const data = await api("/api/health");
    const configured = data.model?.configured === true;
    badge.classList.toggle("configured", configured);
    badge.textContent = configured
      ? `${pick(data.model.model, "模型")} 已配置 · 支持概念解释与证据分析，实际调用以回答标记为准`
      : "模型未配置 · 当前使用本地证据流程";
    state.loaded.modelHealth = true;
  } catch (error) {
    badge.classList.remove("configured");
    badge.textContent = "模型配置状态不可用 · 实际调用以每次回答标记为准";
    throw error;
  }
}
async function api(path, options = {}, timeoutMs = 35_000) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, { headers: {"Accept":"application/json", ...(options.body ? {"Content-Type":"application/json"} : {})}, ...options, signal: controller.signal, cache: "no-store" });
    const raw = await response.text();
    let data = {};
    try { data = raw ? JSON.parse(raw) : {}; }
    catch { throw new Error("服务返回了无法解析的数据"); }
    if (!response.ok) throw new Error(pick(data.error, data.message, `请求失败（HTTP ${response.status}）`));
    return data;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("请求超时，请检查采集服务或网络状态");
    if (error instanceof TypeError && window.location.protocol === "file:") throw new Error("请通过项目提供的本地服务打开界面");
    throw error;
  } finally { window.clearTimeout(timer); }
}
function navigate(page) {
  if (!pageMeta[page]) return;
  state.page = page;
  $$(".page").forEach(node => node.classList.toggle("active", node.dataset.page === page));
  $$(".nav-item").forEach(node => {
    const current = node.dataset.nav === page;
    node.classList.toggle("active", current);
    if (current) node.setAttribute("aria-current", "page"); else node.removeAttribute("aria-current");
  });
  $("#pageTitle").textContent = pageMeta[page][0];
  $("#sectionEyebrow").textContent = pageMeta[page][1];
  window.scrollTo({top:0,behavior:"smooth"});
  const reportError = error => toast(`页面加载失败：${error.message}`, "error");
  if (page === "knowledge" && !state.loaded.knowledge) loadDocuments().catch(reportError);
  if (page === "assets" && !state.loaded.assets) loadAssets().catch(reportError);
  if (page === "runs") loadRuns().catch(reportError);
  if (page === "vulnerabilities" && !state.loaded.vulnerabilities) loadVulnerabilities().catch(reportError);
  if (page === "sources" && !state.loaded.dashboard) loadDashboard().catch(reportError);
  if (page === "assistant" && !state.loaded.modelHealth) loadModelHealth().catch(() => {});
}

function renderStats() {
  const stats = state.dashboard?.stats || {};
  const rows = [
    {label:"漏洞实体",value:stats.vulnerabilities,hint:"跨来源归并后的漏洞",icon:"radar",style:"mint"},
    {label:"知识文档",value:stats.documents,hint:"可溯源的原始记录",icon:"stack",style:"cyan"},
    {label:"证据关系",value:stats.claims,hint:"带文档依据的结构化事实",icon:"link",style:""},
    {label:"健康数据源",value:stats.healthy_sources,hint:`已登记 ${count(stats.sources)} 个来源`,icon:"activity",style:"amber"},
  ];
  const target = $("#statsGrid"); target.replaceChildren();
  for (const row of rows) {
    const card = element("div", `stat-card ${row.style}`);
    const pict = append(element("div", "stat-icon"), icon(row.icon));
    append(card, pict, element("div", "stat-label", row.label), element("div", "stat-value", count(row.value)), element("div", "stat-hint", row.hint));
    target.append(card);
  }
  $("#documentCount").textContent = count(stats.documents);
  $("#sourceCount").textContent = count(stats.sources);
  $("#vulnCount").textContent = count(stats.vulnerabilities);
}
function formatLatency(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return "暂无样本";
  const hours = Math.max(0, Number(value));
  if (hours < 1) return `${Math.round(hours * 60)} 分钟`;
  if (hours < 48) return `${Number(hours.toFixed(1))} 小时`;
  return `${Number((hours / 24).toFixed(1))} 天`;
}
function renderLatency() {
  const latency = state.dashboard?.latency || {};
  const target = $("#latencyGrid"); target.replaceChildren();
  for (const [scope, title, description] of [
    ["live", "在线采集", "真实联网文档的首次采集延迟"],
    ["demo_snapshot", "离线快照", "历史公开样例的导入延迟，不能代表在线监测时效"],
  ]) {
    const bucket = latency[scope] || {};
    const card = element("article", `latency-card ${scope}`);
    const head = element("div", "latency-card-head");
    append(head, element("strong", "", title), element("span", "", `${count(bucket.samples)} 条有效样本`));
    append(card, head, element("div", "latency-main", formatLatency(bucket.p95_hours)),
           element("span", "latency-caption", "发布至首次采集 · P95"));
    const secondary = element("div", "latency-secondary");
    append(secondary, element("span", "", `P50 ${formatLatency(bucket.p50_hours)}`),
           element("span", "", `最大 ${formatLatency(bucket.max_hours)}`));
    append(card, secondary, element("p", "", description));
    target.append(card);
  }
}
function intelligenceRow(item) {
  const row = element("div", "intel-row");
  const mark = append(element("span", "intel-mark"), icon("shield"));
  const copy = element("div", "intel-copy");
  append(copy, element("strong", "", pick(item.title, item.canonical_id, "未命名漏洞")), element("small", "", `${pick(item.canonical_id, "未编号")}  ·  ${pick(item.product, "产品待确认")}`));
  const action = element("button", "table-action", "查看"); action.type = "button"; action.addEventListener("click", () => openDetail(item.canonical_id));
  return append(row, mark, copy, severityBadge(item), action);
}
function renderOverview() {
  const vulnerabilities = state.vulnerabilities.length ? state.vulnerabilities : list(state.dashboard?.vulnerabilities);
  const vulnTarget = $("#overviewVulnerabilities"); vulnTarget.replaceChildren();
  if (!vulnerabilities.length) empty(vulnTarget, "知识库暂无漏洞记录。可点击“演示采集”导入公开来源快照。");
  else vulnerabilities.slice(0, 4).forEach(item => vulnTarget.append(intelligenceRow(item)));
  const sourceTarget = $("#overviewSources"); sourceTarget.replaceChildren();
  const sources = list(state.dashboard?.sources);
  if (!sources.length) empty(sourceTarget, "暂无数据源状态。");
  else sources.slice(0, 5).forEach(source => sourceTarget.append(sourceRow(source)));
  const runTarget = $("#overviewRuns"); runTarget.replaceChildren();
  const runs = list(state.dashboard?.runs);
  if (!runs.length) empty(runTarget, "暂无采集任务。", "empty-inline");
  else runs.slice(0, 4).forEach(run => runTarget.append(runRow(run, true)));
  const eventTarget = $("#overviewEvents"); eventTarget.replaceChildren();
  const events = list(state.dashboard?.events);
  if (!events.length) empty(eventTarget, "暂无 Agent 执行事件。", "empty-inline");
  else events.slice(0, 5).forEach(event => eventTarget.append(eventRow(event, true)));
}
function sourceRow(source) {
  const status = source.status === "demo" ? "demo" : source.enabled === 0 || source.enabled === false ? "disabled" : cleanStatus(source.status, ["healthy","error","idle"], "idle");
  const row = element("div", "source-row");
  const copy = element("div", "source-row-main");
  append(copy, element("strong", "", pick(source.id, source.name, "未命名来源")), element("small", "", `${pick(categoryNames[source.category], source.category, "未分类")} · ${sourceStatusNames[status]}`));
  return append(row, element("span", `source-dot ${status}`), copy, element("span", "row-time", formatRelative(source.last_success)));
}
function runRow(run, compact = false) {
  const row = element("div", "run-row");
  const copy = element("div", "run-row-main");
  append(copy, element("strong", "", `采集任务 #${pick(run.id, "—")}`), element("small", "", `${formatDate(run.started_at, true)} · ${runStatusLabel(run.status)}`));
  if (!compact) {
    const detail = element("div", "run-detail");
    for (const [label,key] of [["抓取","fetched"],["新增","inserted"],["更新","updated"],["去重","skipped"],["错误","errors"]]) detail.append(element("span", "", `${label} ${count(run[key])}`));
    copy.append(detail);
  }
  return append(row, element("span", `run-mode ${run.mode === "live" ? "live" : ""}`, run.mode === "live" ? "在线" : "演示"), copy);
}
function runStatusLabel(status) { return ({success:"成功",completed:"完成",ok:"成功",running:"运行中",partial:"部分完成",error:"失败",failed:"失败"})[String(status || "").toLowerCase()] || pick(status, "未知"); }
function eventRow(event, compact = false) {
  const status = String(event.status || "").toLowerCase();
  const row = element("div", "event-row");
  const copy = element("div", "event-row-main");
  append(copy, element("strong", "", pick(event.action, "执行事件")), element("small", "", `${pick(event.agent, "系统")} · ${formatDate(event.occurred_at, true)}`));
  if (!compact && event.detail) copy.append(element("span", "event-detail", truncate(event.detail, 240)));
  return append(row, element("span", `event-dot ${["error","failed"].includes(status) ? "error" : ["ok","success"].includes(status) ? "success" : ""}`), copy);
}
async function loadDashboard() {
  try {
    const data = await api("/api/dashboard");
    state.dashboard = data; state.loaded.dashboard = true;
    serviceStatus(true); renderStats(); renderLatency(); renderOverview(); renderSources();
  } catch (error) {
    serviceStatus(false);
    if (!state.loaded.dashboard) {
      empty($("#statsGrid"), error.message, "stat-card loading-card");
      empty($("#latencyGrid"), "无法读取采集延迟统计。", "latency-card loading-card");
      empty($("#overviewSources"), "无法读取数据源状态。");
      empty($("#sourceGrid"), "无法读取数据源状态。请确认服务已启动。", "empty-state");
    }
    throw error;
  }
}
async function loadVulnerabilities() {
  try {
    const data = await api("/api/vulnerabilities");
    state.vulnerabilities = list(data.items); state.loaded.vulnerabilities = true;
    $("#vulnCount").textContent = count(state.dashboard?.stats?.vulnerabilities ?? state.vulnerabilities.length);
    renderVulnerabilities(); renderOverview();
  } catch (error) {
    if (!state.loaded.vulnerabilities) renderTableError($("#vulnTableBody"), 6, error.message);
    throw error;
  }
}
function renderVulnerabilities() {
  const query = $("#vulnSearch").value.trim().toLowerCase();
  const severity = $("#severityFilter").value;
  const filtered = state.vulnerabilities.filter(item => {
    if (severity && severityOf(item) !== severity) return false;
    return !query || [item.canonical_id,item.title,item.summary,item.product].some(value => String(value || "").toLowerCase().includes(query));
  });
  const body = $("#vulnTableBody"); body.replaceChildren();
  if (!filtered.length) {
    const tr = element("tr"); const td = element("td", "table-empty", state.vulnerabilities.length ? "没有匹配的情报，请调整筛选条件。" : "暂无漏洞记录。请先进行演示或在线采集。");
    td.colSpan = 6; tr.append(td); body.append(tr); return;
  }
  for (const item of filtered) {
    const tr = element("tr");
    const first = element("td"); append(first, element("strong", "table-primary", pick(item.title, item.canonical_id, "未命名漏洞")), element("span", "table-secondary mono", pick(item.canonical_id, "未编号")));
    const product = element("td", "", pick(item.product, "待确认"));
    const score = element("td"); append(score, severityBadge(item), element("span", "table-secondary mono", item.cvss === null || item.cvss === undefined ? "CVSS —" : `CVSS ${item.cvss}`));
    const date = element("td", "", formatDate(item.published_at));
    const source = element("td", "", pick(item.source_id, "—"));
    const actionCell = element("td"); const action = element("button", "table-action", "证据详情"); action.type = "button"; action.addEventListener("click", () => openDetail(item.canonical_id)); actionCell.append(action);
    append(tr, first, product, score, date, source, actionCell); body.append(tr);
  }
}
function sectionBlock(title) { const block = element("section", "detail-block"); block.append(element("h3", "", title)); return block; }
function detailEmpty(block, text) { block.append(element("div", "detail-empty", text)); }
function timelineEntries(documents) {
  const entries = [];
  documents.forEach(doc => {
    const source = pick(doc.source_id, "未知来源");
    const modeName = doc.mode === "demo" ? "离线快照" : "在线采集";
    if (doc.published_at) entries.push({time: doc.published_at, kind: "publish", title: "来源发布", detail: `${source} 发布该情报${doc.kind === "vulnerability" ? "（漏洞公告）" : `（${pick(kindNames[doc.kind], doc.kind, "文档")}）`}`});
    if (doc.updated_at) entries.push({time: doc.updated_at, kind: "update", title: "来源更新", detail: `${source} 更新了记录内容`});
    if (doc.first_seen) entries.push({time: doc.first_seen, kind: "collect", title: "首次采集", detail: `${source} · ${modeName}入库，延迟统计计入 ${doc.mode === "demo" ? "快照" : "在线"}口径`});
  });
  return entries.filter(entry => entry.time).sort((a, b) => new Date(a.time) - new Date(b.time));
}
function renderTimeline(target, documents) {
  const entries = timelineEntries(documents);
  const block = sectionBlock(`情报时间线 · ${entries.length}`);
  if (!entries.length) { detailEmpty(block, "暂无可用的时间戳（来源未提供发布时间）。"); target.append(block); return; }
  const list_ = element("ol", "timeline");
  entries.forEach(entry => {
    const item = element("li", `timeline-item ${entry.kind}`);
    append(item, element("span", "timeline-dot"), element("time", "timeline-time", formatDate(entry.time, true)),
           element("strong", "", entry.title), element("small", "", entry.detail));
    list_.append(item);
  });
  block.append(list_); target.append(block);
}
function closeDetail() {
  $("#detailDrawer").classList.remove("open");
  $("#detailDrawer").setAttribute("aria-hidden", "true");
  $("#drawerBackdrop").hidden = true;
  document.body.classList.remove("drawer-open");
  state.detailRequest += 1;
  if (state.detailReturnFocus?.isConnected) state.detailReturnFocus.focus();
  state.detailReturnFocus = null;
}
async function openDetail(id) {
  if (!id) return;
  if (!$("#detailDrawer").classList.contains("open")) state.detailReturnFocus = document.activeElement;
  const token = ++state.detailRequest;
  $("#drawerBackdrop").hidden = false;
  $("#detailDrawer").classList.add("open");
  $("#detailDrawer").setAttribute("aria-hidden", "false");
  $("#detailDrawer").focus();
  document.body.classList.add("drawer-open");
  empty($("#detailContent"), "正在加载证据、关系和资产匹配…", "detail-loading");
  try {
    const data = await api(`/api/vulnerabilities/${encodeURIComponent(id)}`);
    if (token === state.detailRequest) renderDetail(id, data);
  } catch (error) {
    if (token === state.detailRequest) empty($("#detailContent"), `无法加载详情：${error.message}`, "detail-empty");
  }
}
function renderDetail(id, data) {
  const target = $("#detailContent"); target.replaceChildren();
  const documents = list(data.documents), claims = list(data.claims), assets = list(data.assets);
  const main = documents[0] || state.vulnerabilities.find(item => item.canonical_id === id) || {};
  append(target, element("span", "detail-id mono", id), element("h2", "detail-title", pick(main.title, "情报详情")), element("p", "detail-summary", pick(main.summary, "暂无摘要，请核验下方原始来源。")));
  const meta = element("div", "detail-meta"); append(meta, severityBadge(main), element("span", "", `产品：${pick(main.product, "待确认")}`), element("span", "", `发布：${formatDate(main.published_at)}`)); target.append(meta);
  renderTimeline(target, documents);
  const docBlock = sectionBlock(`原始来源 · ${documents.length}`);
  if (!documents.length) detailEmpty(docBlock, "暂无可展示的原始来源文档。");
  documents.forEach(doc => {
    const card = element("article", "detail-doc");
    append(card, element("strong", "", pick(doc.title, "未命名文档")), element("small", "", `${pick(kindNames[doc.kind], doc.kind, "文档")} · ${pick(doc.source_id, "未知来源")} · ${formatDate(doc.published_at)}`));
    if (doc.summary) card.append(element("small", "", truncate(doc.summary, 280)));
    if (safeURL(doc.url)) { const link = externalLink(doc.url, "核验原文"); link.append(icon("external")); card.append(link); }
    else if (doc.url) card.append(element("small", "untrusted-url", String(doc.url)));
    docBlock.append(card);
  }); target.append(docBlock);
  const claimBlock = sectionBlock(`结构化事实 · ${claims.length}`);
  if (!claims.length) detailEmpty(claimBlock, "暂无经来源文档支持的结构化事实。");
  claims.forEach(claim => {
    const card = element("article", "detail-claim");
    append(card, element("strong", "", `${pick(predicateNames[claim.predicate], claim.predicate, "关联")}: ${pick(claim.object, "—")}`), element("small", "", `${pick(claim.source_id, claim.document_title, "来源待确认")} · ${formatDate(claim.published_at)}`));
    if (claim.evidence) card.append(element("p", "", truncate(claim.evidence, 500)));
    if (claim.confidence !== null && claim.confidence !== undefined) {
      const level = Math.max(0, Math.min(1, number(claim.confidence)));
      const meter = element("progress", `confidence-meter ${level >= 0.85 ? "high" : level >= 0.65 ? "mid" : "low"}`);
      meter.max = 100;
      meter.value = Math.round(level * 100);
      meter.setAttribute("aria-label", "来源置信度");
      append(card, element("span", "confidence", `来源置信度 ${Math.round(level * 100)}%`), meter);
    }
    claimBlock.append(card);
  }); target.append(claimBlock);
  const related = list(data.related);
  if (related.length) {
    const relatedBlock = sectionBlock(`自动关联知识 · ${related.length}`);
    related.forEach(doc => {
      const card = element("article", "detail-doc related-doc");
      append(card, element("strong", "", pick(doc.title, "未命名文档")), element("small", "", `${pick(kindNames[doc.kind], doc.kind, "文档")} · ${pick(doc.source_id, "未知来源")} · ${formatDate(doc.published_at)}`));
      if (doc.association) card.append(element("span", "association-tag", doc.association));
      if (safeURL(doc.url)) { const link = externalLink(doc.url, "核验原文"); link.append(icon("external")); card.append(link); }
      else if (doc.url) card.append(element("small", "untrusted-url", String(doc.url)));
      relatedBlock.append(card);
    });
    target.append(relatedBlock);
  }
  const assetBlock = sectionBlock(`授权资产匹配 · ${assets.length}`);
  if (!assets.length) detailEmpty(assetBlock, "暂无同产品的授权资产记录。此处不会主动扫描互联网资产。");
  assets.forEach(asset => {
    const card = element("article", "detail-asset");
    append(card, element("strong", "", `${pick(asset.name, "未命名资产")} · ${pick(impactNames[asset.status], "待核验")}`), element("small", "", `${pick(asset.product, "未知产品")} ${pick(asset.version, "未知版本")} · ${pick(exposureNames[asset.exposure], asset.exposure, "暴露面未知")} · 关联优先级 ${pick(asset.priority, "—")}`));
    if (list(asset.evidence).length) card.append(element("small", "", `证据：${list(asset.evidence).map(item => pick(item.title,item.source_id,"来源")).join("、")}`));
    assetBlock.append(card);
  }); target.append(assetBlock);
}

async function loadDocuments() {
  const token = ++state.documentRequest;
  const query = $("#documentSearch").value.trim();
  const kind = $("#kindFilter").value;
  const params = new URLSearchParams();
  params.set("limit", String(DOCUMENT_LIMIT));
  if (query) params.set("query", query); if (kind) params.set("kind", kind);
  const target = $("#documentGrid"); empty(target, "正在检索知识库…", "empty-state");
  $("#documentResultNote").textContent = "正在检索…";
  try {
    const data = await api(`/api/documents${params.size ? `?${params}` : ""}`);
    if (token !== state.documentRequest) return;
    state.documents = list(data.items); state.loaded.knowledge = true;
    renderDocuments();
  } catch (error) {
    if (token === state.documentRequest) {
      empty(target, `检索失败：${error.message}`, "empty-state");
      $("#documentResultNote").textContent = "本次检索未完成";
    }
    throw error;
  }
}
function renderDocuments() {
  const filtered = $("#documentSearch").value.trim() || $("#kindFilter").value;
  const total = number(state.dashboard?.stats?.documents);
  const loaded = state.documents.length;
  let note = filtered ? `找到 ${count(loaded)} 条匹配文档` : `已展示 ${count(loaded)} 篇文档`;
  if (loaded >= DOCUMENT_LIMIT) {
    if (filtered) note = `展示前 ${count(loaded)} 条匹配文档，请缩小检索范围。`;
    else if (total > loaded) note = `展示最新 ${count(loaded)} / ${count(total)} 篇文档，请用关键词查找更早记录。`;
    else if (!total) note = `展示最新 ${count(loaded)} 篇文档，可能还有更早记录。`;
  }
  $("#documentResultNote").textContent = note;
  const target = $("#documentGrid"); target.replaceChildren();
  if (!state.documents.length) { empty(target, "没有找到匹配的文档。尝试清除关键词或切换类别。", "empty-state"); return; }
  state.documents.forEach(doc => {
    const card = element("article", "document-card");
    const top = element("div", "doc-top"); append(top, element("span", "kind-tag", pick(kindNames[doc.kind],doc.kind,"未分类")), element("span", "doc-date", formatDate(doc.published_at)));
    append(card, top, element("h3", "", pick(doc.title, "未命名文档")), element("p", "", pick(doc.summary, truncate(doc.body, 140), "暂无摘要。")));
    const foot = element("div", "doc-bottom"); foot.append(element("span", "", `${pick(doc.source_id,"来源待确认")} · ${pick(doc.canonical_id,"无关联标识")}`));
    if (safeURL(doc.url)) { const link = externalLink(doc.url, "查看原文"); link.className = "doc-link"; link.append(icon("external")); foot.append(link); }
    else if (doc.url) foot.append(element("span", "untrusted-url", String(doc.url)));
    card.append(foot); target.append(card);
  });
}
function renderSources() {
  const sources = list(state.dashboard?.sources);
  const summary = $("#sourceSummary"); summary.replaceChildren();
  const healthy = sources.filter(source => source.status === "healthy" && source.enabled !== 0 && source.enabled !== false).length;
  const errors = sources.filter(source => source.status === "error").length;
  for (const [label, value] of [["来源总数",sources.length],["当前健康",healthy],["当前异常",errors]]) {
    const card = element("div", "source-summary-card"); append(card, element("span", "", label), element("strong", "", count(value))); summary.append(card);
  }
  const target = $("#sourceGrid"); target.replaceChildren();
  if (!sources.length) { empty(target, "暂无来源配置。请检查项目配置或采集服务。", "empty-state"); return; }
  sources.forEach(source => {
    const status = source.status === "demo" ? "demo" : source.enabled === 0 || source.enabled === false ? "disabled" : cleanStatus(source.status, ["healthy","error","idle"], "idle");
    const card = element("article", `source-card ${status}`);
    const head = element("div", "source-card-head");
    const group = element("div"); append(group, element("div", "source-card-name", pick(source.id, source.name, "未命名来源")), element("div", "source-card-category", pick(categoryNames[source.category],source.category,"未分类")));
    append(head, group, element("span", `source-status ${status}`, sourceStatusNames[status])); card.append(head);
    const meta = element("div", "source-metadata");
    for (const [label,value] of [["类型",pick(source.type,"—")],["最近成功",formatDate(source.last_success,true)],["失败次数",count(source.fail_count)],["接口",safeURL(source.url) ? new URL(safeURL(source.url)).hostname : truncate(pick(source.url,"本地数据"),160)]]) append(meta, element("span","",label), element("strong","",value));
    card.append(meta);
    if (source.last_error) card.append(element("div", "source-error", truncate(source.last_error, 280)));
    card.append(element("div", "source-progress")); target.append(card);
  });
}
async function loadAssets() {
  try { const data = await api("/api/assets"); state.assets = list(data.items); state.loaded.assets = true; renderAssets(); }
  catch (error) { renderTableError($("#assetTableBody"), 6, error.message); throw error; }
}
function renderTableError(body, colspan, message) { body.replaceChildren(); const tr=element("tr"); const td=element("td","table-empty",message); td.colSpan=colspan; tr.append(td); body.append(tr); }
function renderAssets() {
  const body = $("#assetTableBody"); body.replaceChildren();
  if (!state.assets.length) { renderTableError(body, 6, "暂无授权资产。点击“登记资产”开始建立内部清单。"); return; }
  state.assets.forEach(asset => {
    const tr = element("tr");
    const criticality = Math.max(1,Math.min(5,number(asset.criticality)));
    append(tr, element("td", "table-id", pick(asset.name,"未命名资产")), element("td","",pick(asset.product,"—")), element("td","mono",pick(asset.version,"—")));
    const exposure = element("td"); exposure.append(element("span", `exposure-tag ${cleanStatus(asset.exposure,["internet","internal","isolated"],"internal")}`, pick(exposureNames[asset.exposure],asset.exposure,"未知")));
    const level = element("td"); level.append(element("span", `criticality ${criticality >= 4 ? "high" : ""}`, `${criticality} / 5`));
    append(tr, exposure, level, element("td","",pick(asset.owner,"未指定"))); body.append(tr);
  });
}
async function saveAsset(event) {
  event.preventDefault();
  const form = $("#assetForm");
  if (!form.reportValidity()) return;
  const values = Object.fromEntries(new FormData(form));
  values.criticality = Number(values.criticality);
  $("#saveAssetButton").disabled = true;
  try {
    await api("/api/assets", {method:"POST",body:JSON.stringify(values)});
    $("#assetDialog").close(); form.reset(); toast("资产已保存，漏洞影响匹配将使用最新清单。", "success");
    await Promise.allSettled([loadAssets(),loadDashboard()]);
  } catch (error) { toast(`保存失败：${error.message}`, "error"); }
  finally { $("#saveAssetButton").disabled = false; }
}
async function loadRuns() {
  try {
    const data = await api("/api/runs");
    state.runs = list(data.items); state.loaded.runs = true;
    renderRuns(state.runs, list(data.events).length ? data.events : list(state.dashboard?.events));
  } catch (error) { empty($("#runList"), `无法读取运行记录：${error.message}`); throw error; }
  finally { if (state.page === "runs") void loadSelfcheck(); }
}
async function loadSelfcheck() {
  const grid = $("#selfcheckGrid"), summary = $("#selfcheckSummary");
  if (!grid || grid.dataset.loaded === "1" || state.selfcheckPending) return;
  state.selfcheckPending = true;
  try {
    const data = await api("/api/security-selfcheck", {}, 60_000);
    summary.replaceChildren();
    const head = element("div", "selfcheck-head");
    append(head, icon("shield"), element("strong", "", `Agent 安全自检 · ${data.passed}/${data.total} 通过`),
           element("small", "", "项目自定的 OWASP Agentic AI 攻击面映射；全部在临时库上可复现运行"));
    summary.append(head);
    grid.replaceChildren();
    (list(data.checks)).forEach(check => {
      const card = element("article", `selfcheck-card ${check.passed ? "pass" : "fail"}`);
      const top = element("div", "selfcheck-top");
      append(top, element("span", `selfcheck-badge ${check.passed ? "pass" : "fail"}`, check.passed ? "通过" : "未通过"),
             element("span", "selfcheck-area", pick(data.areas?.[check.owasp_area], check.owasp_area)));
      append(card, top, element("strong", "", pick(check.title, check.id)),
             element("small", "", pick(check.evidence, "")));
      grid.append(card);
    });
    grid.dataset.loaded = "1";
  } catch (error) {
    summary.replaceChildren(element("span", "selfcheck-pending", `安全自检暂不可用：${error.message}`));
  } finally { state.selfcheckPending = false; }
}
function renderRuns(runs = state.runs, events = list(state.dashboard?.events)) {
  const runTarget = $("#runList"); runTarget.replaceChildren();
  if (!runs.length) empty(runTarget, "还没有采集任务记录。");
  else runs.forEach(run => runTarget.append(runRow(run)));
  const eventTarget = $("#eventList"); eventTarget.replaceChildren();
  if (!events.length) empty(eventTarget, "还没有 Agent 执行事件。");
  else events.forEach(event => eventTarget.append(eventRow(event)));
}

const welcomeTemplate = $(".welcome-card").cloneNode(true);
function resetSession() {
  state.questionRequest += 1;
  state.sessionId = null;
  state.asking = false;
  $("#askSubmit").disabled = false;
  $("#chatHistory").replaceChildren(welcomeTemplate.cloneNode(true));
  $("#questionInput").focus();
}
function makeChatMessage(role, text, abstained = false) {
  const root = element("article", `chat-message ${role}`);
  const avatar = element("div", "message-avatar", role === "user" ? "我" : "智");
  const body = element("div", "message-body");
  append(body, element("div", "message-label", role === "user" ? "你的问题" : abstained ? "知盾 Agent · 证据不足" : "知盾 Agent"), element("div", `message-content ${abstained ? "abstained" : ""}`, text));
  return append(root, avatar, body);
}
function renderCitations(container, citations) {
  if (!citations.length) return;
  const section = element("section", "message-section"); section.append(element("h4", "", `证据引用 · ${citations.length}`));
  const ul = element("ul", "citation-list");
  citations.forEach((citation,index) => {
    const item = element("li", "citation-item");
    const label = typeof citation === "string" ? citation : `[${pick(citation.number,index+1)}] ${pick(citation.title,citation.source_id,"来源文档")}`;
    const url = typeof citation === "string" ? citation : citation.url;
    if (safeURL(url)) { const link = externalLink(url, label); link.prepend(icon("external")); item.append(link); }
    else { item.append(element("span", "", label)); if (url) item.append(element("span", "citation-excerpt untrusted-url", String(url))); }
    if (citation && typeof citation === "object" && citation.source_id) item.append(element("span", "citation-excerpt", `${citation.source_id} · ${formatDate(citation.published_at)}`));
    ul.append(item);
  }); section.append(ul); container.append(section);
}
function renderTrace(container, trace) {
  if (!trace.length) return;
  const section = element("section", "message-section"); section.append(element("h4", "", `关联与推理路径 · ${trace.length}`));
  const ul = element("ul", "trace-list");
  trace.forEach((step,index) => {
    let description = "";
    if (typeof step === "string") description = step;
    else if (step && typeof step === "object") description = [step.from, pick(predicateNames[step.via],step.via),step.to].filter(Boolean).join(" → ") + (step.evidence ? `（${step.evidence}）` : "");
    const li = element("li", "trace-item"); append(li, element("span", "trace-index mono", String(index+1).padStart(2,"0")), element("span", "", description || "执行步骤")); ul.append(li);
  }); section.append(ul); container.append(section);
}
function renderModelStatus(container, data) {
  if (typeof data.model_used !== "boolean") return;
  const used = data.model_used;
  const model = pick(data.model, "已配置模型");
  const fallback = pick(data.model_fallback_reason, "");
  const role = String(data.model_role || "");
  const card = element("div", `model-status ${used ? "used" : data.model ? "fallback" : "local"}`);
  let title = "本地证据流程";
  let detail = "模型未配置；事实、结论与引用由本地证据流程生成。";
  if (used) {
    const partNames = {planning:"意图规划", evidence_ranking:"候选证据排序", evidence_selection:"证据筛选", concept_explanation:"概念解释", evidence_synthesis:"证据综合分析"};
    const parts = role.split("+").filter(Boolean).map(part => partNames[part] || "问答辅助");
    title = parts.length ? `${model} 已参与 · ${parts.join("与")}` : `${model} 已参与问答辅助`;
    detail = fallback ? `部分步骤回退（${fallback}）；事实、结论与引用仍由本地证据流程生成。`
      : "模型仅辅助处理；事实、结论与引用由本地证据流程生成。";
    if (role.includes("concept_explanation")) detail = "基于模型通用知识解释；未进行实时检索，不代表本地已核验情报。";
    if (role.includes("evidence_synthesis")) detail = "模型依据公开证据分析；程序检查引用原文与编号、数值，具体结论仍需结合来源复核。";
  } else if (data.model) {
    title = `${model} 未参与本次回答 · 本地回退`;
    detail = fallback ? `模型调用未成功（${fallback}），已使用本地证据流程。`
      : "本次模型调用未成功，已使用本地证据流程。";
  }
  append(card, icon(used ? "spark" : "shield"),
         append(element("div", "model-status-copy"), element("strong", "", title), element("small", "", detail)));
  container.append(card);
}
function revealReplyStart(history, reply) {
  if (typeof history.getBoundingClientRect !== "function" ||
      typeof reply.getBoundingClientRect !== "function") return;
  const containerTop = history.getBoundingClientRect().top;
  const replyTop = reply.getBoundingClientRect().top;
  history.scrollTop += replyTop - containerTop - 12;
}
async function askQuestion(question) {
  question = String(question || "").trim();
  if (!question || state.asking) return;
  const token = ++state.questionRequest;
  state.asking = true; $("#askSubmit").disabled = true; $("#questionInput").value = "";
  const history = $("#chatHistory");
  const welcome = $(".welcome-card", history); if (welcome) welcome.remove();
  history.append(makeChatMessage("user", question));
  const pending = makeChatMessage("assistant", "正在理解问题、检索证据并组织回答…");
  history.append(pending); history.scrollTop = history.scrollHeight;
  try {
    const data = await api("/api/ask", {method:"POST",body:JSON.stringify({question,session_id:state.sessionId})}, 100_000);
    if (token !== state.questionRequest) return;
    state.sessionId = pick(data.session_id, state.sessionId, null);
    const reply = makeChatMessage("assistant", pick(data.answer,"系统没有返回可展示的答案。"), Boolean(data.abstained));
    renderModelStatus($(".message-body",reply), data);
    renderCitations($(".message-body",reply), list(data.citations));
    renderTrace($(".message-body",reply), list(data.trace));
    if (data.latency_ms !== undefined) $(".message-label",reply).textContent += ` · ${Math.round(number(data.latency_ms))} ms`;
    const followReply = history.scrollHeight - history.scrollTop - history.clientHeight <= 80;
    pending.replaceWith(reply);
    if (followReply) revealReplyStart(history, reply);
  } catch (error) {
    if (token === state.questionRequest) {
      const reply = makeChatMessage("assistant", `问答请求失败：${error.message}`, true);
      const followReply = history.scrollHeight - history.scrollTop - history.clientHeight <= 80;
      pending.replaceWith(reply);
      if (followReply) revealReplyStart(history, reply);
    }
  } finally {
    if (token === state.questionRequest) {
      state.asking = false; $("#askSubmit").disabled = false;
      $("#questionInput").focus();
    }
  }
}
async function collect(mode) {
  if (state.collecting) return;
  state.collecting = true;
  $$(".collect-button").forEach(button => button.disabled = true);
  toast(mode === "demo" ? "正在导入演示用公开情报快照…" : "正在连接公开来源，请等待采集完成…", "info");
  try {
    const result = await api("/api/collect", {method:"POST",body:JSON.stringify({mode})}, mode === "live" ? 120_000 : 65_000);
    if (result.status === "queued") {
      toast(pick(result.message, "在线采集已排队，可在运行与轨迹页查看进度。"), "info");
      for (const delay of [3000, 12000]) {
        window.setTimeout(() => { Promise.allSettled([loadDashboard(),loadVulnerabilities(),loadRuns()]); }, delay);
      }
    }
    else {
      const run = result.run || result;
      const message = `采集${runStatusLabel(pick(run.status,"完成"))}：抓取 ${count(run.fetched)}，新增 ${count(run.inserted)}，更新 ${count(run.updated)}，去重 ${count(run.skipped)}，错误 ${count(run.errors)}。`;
      toast(message, number(run.errors) ? "info" : "success");
    }
    await Promise.allSettled([loadDashboard(),loadVulnerabilities(),loadRuns(), ...(state.loaded.knowledge ? [loadDocuments()] : [])]);
  } catch (error) { toast(`采集失败：${error.message}`, "error"); await Promise.allSettled([loadDashboard(),loadRuns()]); }
  finally { state.collecting = false; $$(".collect-button").forEach(button => button.disabled = false); }
}
function handleGlobalClick(event) {
  const nav = event.target.closest("[data-nav]"); if (nav) { navigate(nav.dataset.nav); return; }
  const jump = event.target.closest("[data-jump]"); if (jump) { navigate(jump.dataset.jump); return; }
  const trigger = event.target.closest("[data-collect]"); if (trigger) { collect(trigger.dataset.collect); return; }
  const suggestion = event.target.closest("[data-question]"); if (suggestion) askQuestion(suggestion.dataset.question);
}
async function refreshPage() {
  const page = state.page;
  try {
    if (page === "runs") {
      $("#selfcheckGrid").dataset.loaded = "";
      $("#selfcheckSummary").replaceChildren(element("span", "selfcheck-pending", "Agent 安全自检正在重新运行…"));
      await Promise.all([loadDashboard(),loadRuns()]);
    } else if (page === "knowledge") await loadDocuments();
    else if (page === "assets") await loadAssets();
    else if (page === "vulnerabilities") await loadVulnerabilities();
    else if (page === "assistant") await loadModelHealth(true);
    else await loadDashboard();
    toast("页面数据已刷新。", "success");
  } catch (error) { toast(`刷新失败：${error.message}`, "error"); }
}
document.addEventListener("click", handleGlobalClick);
$("#refreshButton").addEventListener("click", refreshPage);
$("#runsRefreshButton").addEventListener("click", refreshPage);
$("#vulnSearch").addEventListener("input", renderVulnerabilities);
$("#severityFilter").addEventListener("change", renderVulnerabilities);
$("#documentSearchForm").addEventListener("submit", event => { event.preventDefault(); loadDocuments().catch(() => {}); });
$("#kindFilter").addEventListener("change", () => loadDocuments().catch(() => {}));
function bindQuestionComposer() {
  const input = $("#questionInput");
  const form = $("#askForm");
  let composing = false;
  input.addEventListener("compositionstart", () => { composing = true; });
  input.addEventListener("compositionend", () => { composing = false; });
  input.addEventListener("blur", () => { composing = false; });
  form.addEventListener("submit", event => {
    event.preventDefault();
    if (!composing) askQuestion(input.value);
  });
  input.addEventListener("keydown", event => {
    // Some WebKit IMEs end composition before the confirming keydown and
    // report isComposing=false; keyCode 229 still identifies that IME event.
    if (composing || event.isComposing || event.keyCode === 229) return;
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      if (!event.repeat) form.requestSubmit();
    }
  });
}
bindQuestionComposer();
$("#newSessionButton").addEventListener("click", resetSession);
$("#drawerBackdrop").addEventListener("click", closeDetail);
$("#closeDrawerButton").addEventListener("click", closeDetail);
document.addEventListener("keydown", event => {
  const drawer = $("#detailDrawer");
  if (!drawer.classList.contains("open")) return;
  if (event.key === "Escape") { closeDetail(); return; }
  if (event.key !== "Tab") return;
  const focusable = $$("a[href],button:not([disabled])", drawer);
  if (!focusable.length) { event.preventDefault(); drawer.focus(); return; }
  const first = focusable[0], last = focusable[focusable.length - 1];
  if (event.shiftKey && (document.activeElement === first || document.activeElement === drawer)) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && (document.activeElement === last || document.activeElement === drawer)) { event.preventDefault(); first.focus(); }
});
$("#addAssetButton").addEventListener("click", () => $("#assetDialog").showModal());
$("#closeAssetDialog").addEventListener("click", () => $("#assetDialog").close());
$("#cancelAssetDialog").addEventListener("click", () => $("#assetDialog").close());
$("#assetForm").addEventListener("submit", saveAsset);

Promise.allSettled([loadDashboard(),loadVulnerabilities()]).then(results => {
  if (results.every(result => result.status === "rejected")) toast("无法连接本地 API，请按项目运行说明启动服务。", "error");
});
