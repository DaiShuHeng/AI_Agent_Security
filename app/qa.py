"""Grounded Chinese security Q&A with bounded graph traversal and abstention."""

from __future__ import annotations

import re
import time
import uuid
import hashlib
from typing import Any

from .db import Database
from .intelligence import CVE_RE, GHSA_RE, asset_impacts, infer_product, product_key, related_knowledge
from . import llm
from .concepts import concept_question, evidence_question, AI_SECURITY_FALLBACK
from .prompts import PROMPT_VERSION


INTENTS = {
    "asset": ("资产", "服务器", "部署", "哪些机器", "asset", "host"),
    "fix": ("修复", "升级", "补丁", "缓解", "mitigation", "fix", "patch"),
    "poc": ("poc", "验证代码", "利用代码", "exploit"),
    "risk": ("风险", "优先级", "影响", "危害", "严重", "高危", "cvss", "severity", "critical"),
    "paper": ("论文", "研究", "paper", "arxiv", "关联分析", "相关文章", "分析文章"),
    "standard": ("标准", "规范", "standard", "nist", "iso"),
    "policy": ("政策", "法规", "办法", "条例", "policy", "regulation"),
    "attack": ("攻击链", "利用链", "attack chain", "kill chain"),
    "kev": ("kev", "在野利用", "已被利用", "已知利用", "known exploited"),
}

# 只有包含指代或延续措辞的问题才允许继承上一轮实体；话题切换的问题
# （如先问 CVE 再问"有哪些政策法规"）不得被旧上下文劫持路由。
FOLLOWUP_MARKERS = (
    "它", "该漏洞", "这个漏洞", "上述", "刚才", "前面", "继续", "接着",
    "那么它", "再问", "还有呢", "呢？", "呢?", "这个", "那个",
)

# 盘点类问题（"有哪些高危漏洞"）按问题主题过滤受影响产品，而不是
# 机械列出最新 8 条。家族成员均以 product_key 归一后的键匹配。
TOPIC_FAMILIES = {
    "inference": {
        "label": "AI 推理框架",
        "match": ("推理框架", "推理服务", "推理引擎", "推理组件", "inference framework",
                  "模型服务", "模型部署", "llm serving"),
        "products": ("ollama", "vllm", "lmdeploy", "llama-cpp-python", "llama-cpp",
                     "triton", "triton inference server", "tensorrt", "sglang",
                     "ray serve", "ray-serve", "openllm", "xinference", "mindie",
                     "text-generation-inference", "tgi", "localai", "koboldcpp",
                     "minicpm", "mnn"),
    },
    "agent": {
        "label": "智能体与编排框架",
        "match": ("智能体", "agent 框架", "agent框架", "agentic", "编排框架", "工作流引擎"),
        "products": ("langchain", "langflow", "langgraph", "llama-index", "llamaindex",
                     "autogen", "crewai", "smolagents", "agno", "dify", "coze",
                     "n8n", "camel", "semantic-kernel", "semantic kernel", "letta",
                     "memgpt", "openai agents"),
    },
    "modelhub": {
        "label": "模型仓库与训练平台",
        "match": ("模型仓库", "模型 hub", "model hub", "hugging face", "huggingface",
                  "魔搭", "modelscope", "训练平台", "机器学习平台"),
        "products": ("huggingface", "hugging face", "transformers", "modelscope",
                     "gradio", "datasets", "timm", "peft", "diffusers"),
    },
    "mlops": {
        "label": "MLOps 与 AI 供应链",
        "match": ("mlops", "ml 供应链", "模型供应链", "ai 供应链", "实验平台"),
        "products": ("mlflow", "kubeflow", "airflow", "metaflow", "clearml",
                     "label-studio", "jupyter", "jupyterlab", "mlflow-ui", "pyspark"),
    },
}


def _portfolio_topic(question: str) -> dict[str, Any] | None:
    lower = question.casefold()
    for family in TOPIC_FAMILIES.values():
        if any(marker in lower for marker in family["match"]):
            return family
    return None


def _vulnerability_overview(question: str, intents: set[str], family: dict[str, Any] | None) -> bool:
    """A request for vulnerability findings outranks a generic source cue."""
    if intents & {"paper", "standard", "policy"}:
        return False
    if family:
        return True
    lower = question.casefold()
    return ("漏洞" in lower or "vulnerabilit" in lower) and any(
        term in lower for term in (
            "最近", "最新", "近期", "当前", "目前", "哪些", "有哪些", "列出",
            "给出", "汇总", "盘点", "修复建议", "修复措施", "高危",
            "recent", "latest", "list", "recommendation"))


def _is_followup(question: str) -> bool:
    return any(marker in question for marker in FOLLOWUP_MARKERS)


def _intents(question: str) -> set[str]:
    lower = question.lower()
    return {name for name, terms in INTENTS.items() if any(term in lower for term in terms)}


def _citation(doc: dict[str, Any], number: int) -> dict[str, Any]:
    return {"number": number, "title": doc["title"], "url": doc["url"],
            "source_id": doc["source_id"], "published_at": doc.get("published_at"),
            "document_id": doc["id"]}


_GENERIC_CHINESE = (
    "有哪些", "有什么", "列出", "请问", "关于", "相关", "介绍", "具体", "多少",
    "是什么", "为什么", "如何", "是否", "最新", "领域", "安全", "人工智能",
    "大模型", "政策", "法规", "标准", "规范", "论文", "研究", "案例", "这个",
    "哪个", "哪些", "什么", "以及", "和", "的", "了", "是", "有", "请",
)
_GENERIC_ENGLISH = {
    "ai", "security", "what", "which", "show", "list", "about", "the", "for",
    "and", "paper", "papers", "standard", "standards", "policy", "policies",
    "regulation", "regulations", "research", "recent", "latest", "please",
}


def _knowledge_terms(question: str) -> list[str]:
    """Keep user-supplied subjects; category words alone cannot justify an answer."""
    residual = question.replace("适用对象", "适用范围").replace("适用人群", "适用范围")
    for word in sorted(_GENERIC_CHINESE, key=len, reverse=True):
        residual = residual.replace(word, " ")
    residual = re.sub(r"\bAI\b", " ", residual, flags=re.I)
    cjk = re.findall(r"[\u4e00-\u9fff]{2,}", residual)
    latin = [term for term in re.findall(r"[A-Za-z][A-Za-z0-9_.-]{1,}", residual)
             if term.lower() not in _GENERIC_ENGLISH]
    return list(dict.fromkeys(cjk + latin))[:6]


class AnswerEngine:
    def __init__(self, db: Database, *, allow_model: bool = True):
        self.db = db
        self.allow_model = allow_model
        self.sessions: dict[str, dict[str, str]] = {}

    def _known_product(self, question: str) -> str:
        """Recognize newly ingested products without a hard-coded package list."""
        lower = question.casefold()
        for product in self.db.known_products():
            if len(product) < 3:
                continue
            if re.search(r"(?<![a-z0-9])" + re.escape(product.casefold()) + r"(?![a-z0-9])", lower):
                return product
        return ""

    def ask(self, question: str, session_id: str | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        question = question.strip()[:1000]
        if not question:
            raise ValueError("问题不能为空")
        if not session_id or not re.fullmatch(r"[a-zA-Z0-9-]{1,64}", session_id):
            session_id = str(uuid.uuid4())
        state = self.sessions.get(session_id, {})
        if len(self.sessions) > 200:
            for stale in list(self.sessions)[:100]:
                self.sessions.pop(stale, None)
        intents = _intents(question)
        local_intents = set(intents)
        topic_family = _portfolio_topic(question)
        question_digest = hashlib.sha256(question.encode("utf-8")).hexdigest()[:16]
        self.db.event(None, "问答规划代理", "意图拆解", "ok",
                      f"question_sha256_prefix={question_digest}; chars={len(question)}; intents={','.join(sorted(intents))}")
        semantic_terms: list[str] = []
        planner = "local"
        model_configured = self.allow_model and llm.enabled()
        model_plan_succeeded = False
        concept_mode = concept_question(question, bool(state.get("concept_question")))
        model_mode = ""
        model_fallback_reason = None
        if model_configured and not concept_mode:
            try:
                model_plan = llm.plan(question)
                intents.update(set(model_plan.get("intents", [])) - {"asset", "poc", "kev"})
                semantic_terms = model_plan.get("search_terms", [])
                model_mode = model_plan.get("answer_mode", "")
                planner = "llm-assisted"
                model_plan_succeeded = True
                self.db.event(None, "问答规划代理", "模型语义规划", "ok",
                              f"intents={','.join(model_plan.get('intents', []))}; search_term_count={len(semantic_terms)}")
            except Exception as exc:
                model_fallback_reason = type(exc).__name__
                self.db.event(None, "问答规划代理", "模型语义规划", "fallback", type(exc).__name__)
        cves = [m.upper() for m in CVE_RE.findall(question)]
        ghsas = [m.upper() for m in GHSA_RE.findall(question)]
        explicit_ids = cves or ghsas
        new_product = infer_product(question) or self._known_product(question)
        followup = _is_followup(question)
        if explicit_ids:
            canonical = explicit_ids[0]
            product = new_product
        elif new_product:
            canonical = ""
            product = new_product
        elif followup:
            canonical = state.get("canonical", "")
            product = state.get("product", "")
        else:
            canonical = ""
            product = ""
        high_only = any(word in question.lower() for word in
                        ("高危", "高风险", "critical", "high severity"))
        concept_mode = concept_mode or concept_question(question, bool(state.get("concept_question")), model_mode)
        if concept_mode and not explicit_ids:
            result = self._answer_concept(question, session_id, state, model_configured)
        elif canonical:
            result = self._answer_vulnerability(canonical, intents, session_id, product)
        elif not product and _vulnerability_overview(question, local_intents, topic_family):
            result = self._answer_portfolio(
                question, local_intents, session_id,
                high_only=any(word in question.lower() for word in
                              ("高危", "高风险", "critical", "high severity")))
        elif evidence_question(question):
            result = self._answer_knowledge(question, local_intents, session_id, semantic_terms)
        elif product and high_only:
            result = self._answer_portfolio(question, local_intents, session_id,
                                            high_only=True, product_filter=product)
        elif product:
            result = self._answer_product(product, intents, session_id)
        elif topic_family or (intents & {"asset", "fix", "risk"}
                              and not intents & {"paper", "standard", "policy"}):
            # 盘点类回答的资产/修复维度只由问题本身决定；模型规划可细化
            # 检索词与排序，但不得把用户没有问的维度塞进答案。
            result = self._answer_portfolio(
                question, local_intents, session_id,
                high_only=any(word in question.lower() for word in
                              ("高危", "高风险", "critical", "high severity")))
        else:
            result = self._answer_knowledge(question, intents, session_id, semantic_terms)
        model_explained = result.pop("_model_explained", False)
        model_synthesized = False
        model_ranked = result.pop("_model_ranked", False)
        skip_selection = result.pop("_skip_evidence_selection", False)
        skip_synthesis = result.pop("_skip_evidence_synthesis", False)
        model_fallback_reason = result.pop("_model_fallback_reason", None) or model_fallback_reason
        # Public evidence only; private asset conclusions stay in the deterministic answer.
        if (model_configured and model_plan_succeeded and not concept_mode and not skip_synthesis
                and not result["abstained"] and result["citations"] and "asset" not in local_intents):
            try:
                cards = self._public_evidence_cards(result["citations"])
                explanation = llm.synthesize_evidence(question, cards)
                result["answer"] = explanation + "\n\n结构化证据核对：\n" + result["answer"]
                result["answer_basis"] = "evidence_synthesis"
                model_synthesized = True
                skip_selection = True
                self.db.event(None, "证据分析代理", "模型证据综合", "ok", f"cards={len(cards)}; prompt={PROMPT_VERSION}")
            except Exception as exc:
                model_fallback_reason = type(exc).__name__
                self.db.event(None, "证据分析代理", "模型证据综合", "fallback", type(exc).__name__)
        model_selected = False
        if (model_plan_succeeded and not result["abstained"]
                and not skip_selection):
            try:
                selected_answer = self._select_answer_evidence(question, result["answer"], intents)
                if selected_answer:
                    result["answer"] = selected_answer
                    model_selected = True
                    self.db.event(None, "证据筛选代理", "GLM 段落选择", "ok",
                                  f"model={llm.status()['model']}; answer_chars={len(selected_answer)}")
            except Exception as exc:
                model_fallback_reason = type(exc).__name__
                self.db.event(None, "证据筛选代理", "GLM 段落选择", "fallback", type(exc).__name__)
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
        result["session_id"] = session_id
        result["planner"] = planner
        result["model"] = llm.status()["model"] if model_configured else None
        roles = ([("planning", model_plan_succeeded), ("evidence_ranking", model_ranked),
                  ("evidence_selection", model_selected), ("concept_explanation", model_explained),
                  ("evidence_synthesis", model_synthesized)])
        active = [name for name, happened in roles if happened]
        result["model_used"] = bool(active)
        result["model_role"] = "+".join(active) or "local"
        result["model_fallback_reason"] = model_fallback_reason
        result["prompt_version"] = PROMPT_VERSION
        result.setdefault("answer_basis", "local_evidence")
        self.db.event(None, "核验代理", "引用与拒答校验", "abstained" if result["abstained"] else "ok",
                      f"citations={len(result['citations'])}; latency_ms={result['latency_ms']}")
        return result

    def _answer_concept(self, question: str, session_id: str, state: dict,
                        model_configured: bool) -> dict[str, Any]:
        history = []
        if state.get("concept_question"):
            history = [{"role": "user", "content": state["concept_question"]},
                       {"role": "assistant", "content": state.get("concept_answer", "")[:1800]}]
        error = None
        if model_configured:
            try:
                answer = llm.explain_concept(question, history)
                self.sessions[session_id] = {"concept_question": question, "concept_answer": answer}
                self.db.event(None, "概念解释代理", "模型通识解释", "ok", f"prompt={PROMPT_VERSION}")
                return {"answer": "通用知识解释（未进行实时情报检索）：\n\n" + answer,
                        "citations": [], "trace": [], "abstained": False,
                        "answer_basis": "general_knowledge", "_model_explained": True,
                        "_skip_evidence_selection": True}
            except Exception as exc:
                error = type(exc).__name__
                self.db.event(None, "概念解释代理", "模型通识解释", "fallback", error)
        if any(term in question.lower().replace(" ", "") for term in ("ai安全", "人工智能安全")):
            return {"answer": "本地基础知识说明：\n\n" + AI_SECURITY_FALLBACK,
                    "citations": [], "trace": [], "abstained": False,
                    "answer_basis": "local_general_knowledge", "_model_fallback_reason": error,
                    "_skip_evidence_selection": True}
        result = self._abstain(session_id, ["这个问题适合概念解释，但模型当前未配置或暂时不可用，"
                                          "本地也没有对应的基础讲解。请稍后重试。"])
        result["_model_fallback_reason"] = error
        return result

    def _public_evidence_cards(self, citations: list[dict]) -> list[dict]:
        cards = []
        with self.db.connect() as connection:
            for citation in citations[:10]:
                row = connection.execute("SELECT * FROM documents WHERE id=?",
                                         (citation["document_id"],)).fetchone()
                if row is None:
                    continue
                doc = self.db._document_dict(row)
                # Never include raw source payloads, claims, assets or session state.
                text = "\n".join(f"{field}: {doc.get(field) or ''}" for field in (
                    "canonical_id", "product", "title", "severity", "cvss", "published_at",
                    "versions", "fixed_versions"))
                text += "\nsummary: " + str(doc.get("summary") or "")[:3000]
                text += "\nbody: " + str(doc.get("body") or "")[:3000]
                cards.append({"id": citation["number"], "text": text})
        return cards

    @staticmethod
    def _select_answer_evidence(question: str, answer: str, intents: set[str]) -> str | None:
        segments = [part.strip() for part in re.split(r"\n\s*\n", answer) if part.strip()]
        if not segments:
            return None
        private = {index for index, part in enumerate(segments)
                   if "演示-虚构" in part or "资产" in part}
        public = [{"id": index, "text": part[:700]} for index, part in enumerate(segments[:20])
                  if index not in private]
        if not public:
            return None
        selected = set(llm.select_evidence(question, public)) | private
        if not selected - private:
            return None
        candidate = "\n\n".join(part for index, part in enumerate(segments) if index in selected)
        # A model may filter irrelevant paragraphs, but it cannot suppress an
        # explicit answer field the user asked for.
        required = {
            "fix": "修复版本证据",
            "risk": "公开来源给出的风险级别",
            "paper": "研究/分析文章",
        }
        if any(tag in intents and label in answer and label not in candidate
               for tag, label in required.items()):
            return None
        return candidate

    def _answer_vulnerability(self, canonical: str, intents: set[str],
                              session_id: str, product_hint: str) -> dict[str, Any]:
        docs = self.db.document_group(canonical)
        if not docs:
            # A targeted indexed lookup works even after thousands of claims.
            resolved = self.db.canonical_for_alias(canonical)
            if resolved:
                canonical = resolved
                docs = self.db.document_group(canonical)
        if not docs:
            return self._abstain(session_id, [f"未在本地知识库找到 {canonical}。请先采集可信来源。"])
        if product_hint:
            docs.sort(key=lambda doc: product_key(doc["product"]) != product_key(product_hint))
        self.sessions[session_id] = {"canonical": canonical, "product": product_hint or docs[0]["product"]}
        doc_by_id = {doc["id"]: doc for doc in docs}
        citations = [_citation(doc, i + 1) for i, doc in enumerate(docs[:8])]
        number_by_id = {c["document_id"]: c["number"] for c in citations}
        # Every fact included in the answer must have a citation number. A large
        # group can exceed the UI citation cap, so ignore uncited source claims.
        claims = [claim for claim in self.db.claims(canonical, limit=1000)
                  if claim["document_id"] in number_by_id]
        grouped: dict[str, list[dict[str, Any]]] = {}
        for claim in claims:
            grouped.setdefault(claim["predicate"], []).append(claim)
        def claim_rows(predicate: str) -> list[dict[str, Any]]:
            rows = grouped.get(predicate, [])
            if product_hint and predicate in {"affected_version", "fixed_version"}:
                rows = [row for row in rows if product_key(doc_by_id[row["document_id"]]["product"])
                        == product_key(product_hint)]
            return rows
        def values(predicate: str) -> list[str]:
            return list(dict.fromkeys(c["object"] for c in claim_rows(predicate)))
        def version_values(predicate: str) -> list[str]:
            rows = claim_rows(predicate)
            products = {product_key(doc_by_id[row["document_id"]]["product"]) for row in rows}
            if len(products) <= 1:
                return list(dict.fromkeys(row["object"] for row in rows))
            return list(dict.fromkeys(
                f"{doc_by_id[row['document_id']]['product']}: {row['object']}" for row in rows))
        def marker(*predicates: str) -> str:
            numbers: list[int] = []
            for predicate in predicates:
                for c in claim_rows(predicate):
                    number = number_by_id.get(c["document_id"])
                    if number is not None and number not in numbers:
                        numbers.append(number)
            return "".join(f"[{number}]" for number in numbers)
        if intents == {"kev"} and not values("known_exploited"):
            return self._abstain(session_id, [
                f"当前入库证据不能确认 {canonical} 是否被 CISA KEV 收录；"
                "请核验 CISA KEV 最新目录，不能把未检索到视为未收录。"
            ])
        trace: list[dict[str, str]] = []
        display_title = docs[0]["title"]
        title_prefix = canonical + "："
        if display_title.startswith(title_prefix):
            display_title = display_title[len(title_prefix):]
        parts = [f"{canonical}：{display_title}。[1]"]
        products = values("affects_product")
        if products:
            parts.append(f"关联产品：{', '.join(products)}。{marker('affects_product')}")
            for name in products:
                trace.append({"from": canonical, "via": "affects_product", "to": name,
                              "evidence": marker("affects_product")})
        if not intents or "risk" in intents:
            severity = values("severity")
            scores = values("cvss")
            epss_values = values("epss")
            if scores or severity:
                score_text = f"CVSS {', '.join(scores)}" if scores else "CVSS 未知"
                parts.append(f"公开来源给出的风险级别：{', '.join(severity) or '未知'}；{score_text}。"
                             f"{marker('severity', 'cvss')}")
            if epss_values:
                parts.append(f"利用可能性（FIRST EPSS，未来 30 天被利用概率，0-1）："
                             f"{', '.join(epss_values)}。{marker('epss')}")
            if len(scores) > 1:
                parts.append("不同来源评分存在差异，需按各自 CVSS 版本及更新时间复核。")
        if not intents or "fix" in intents:
            fixes = version_values("fixed_version")
            if fixes:
                parts.append(f"修复版本证据：{', '.join(fixes)}。建议按厂商公告升级并复测。{marker('fixed_version')}")
            else:
                parts.append("当前证据没有明确修复版本；请查阅厂商公告，不应推测补丁版本。")
        if "risk" in intents or not intents:
            affected = version_values("affected_version")
            if affected:
                parts.append(f"公开影响版本范围：{'; '.join(affected)}。{marker('affected_version')}")
        if "asset" in intents:
            impacts = asset_impacts(self.db, canonical)
            if product_hint:
                impacts = [item for item in impacts if product_key(item["product"]) == product_key(product_hint)]
            affected = [x for x in impacts if x["status"] == "affected"]
            unknown = [x for x in impacts if x["status"] == "unknown"]
            if affected:
                parts.append("本地演示清单中，版本规则匹配的潜在受影响资产：" +
                             "、".join(f"{x['name']} ({x['product']} {x['version']}, 优先级 {x['priority'] if x['priority'] is not None else '待评估'})"
                                     for x in affected) + "。资产与版本来自本地登记，实际暴露及可利用性需人工核验。")
                for asset in affected:
                    trace.append({"from": products[0] if products else canonical,
                                  "via": "local_asset_version_match", "to": asset["name"],
                                  "evidence": "本地授权资产清单 + 公告版本范围"})
            elif impacts:
                parts.append("本地清单没有确认受影响的资产。")
            if unknown:
                parts.append("版本证据不足，待核实资产：" + "、".join(x["name"] for x in unknown) + "。")
            if not impacts:
                parts.append("未登记同产品的本地资产，无法判断本组织的影响范围。")
        if "poc" in intents:
            refs = values("poc_reference")
            parts.append("PoC 元数据链接：" + "、".join(refs[:5]) + marker("poc_reference") if refs else
                         "当前证据未发现已核验 PoC 链接；系统不会执行验证代码。")
        if "kev" in intents:
            if values("known_exploited"):
                parts.append("CISA KEV 来源记录了此漏洞已被利用；请结合该目录的处置要求核验。"
                             + marker("known_exploited"))
            else:
                parts.append("当前入库证据不能确认该漏洞是否被 CISA KEV 收录；不能把未检索到视为未收录。")
        if "attack" in intents:
            parts.append("当前结构化证据不足以确认完整攻击链；可据上方影响产品与版本排查，但不能把可能路径写成已发生攻击。")
        if "paper" in intents or "standard" in intents or "policy" in intents:
            related = related_knowledge(self.db, canonical, products)
            related = [doc for doc in related if doc["id"] not in doc_by_id]
            if related:
                for doc in related[:3]:
                    number = len(citations) + 1
                    citations.append(_citation(doc, number))
                    parts.append(f"关联{doc['kind']}：{doc['title']}（{doc['association']}）。[{number}]")
                    trace.append({"from": canonical, "via": "mentioned_in" if "提及" in doc["association"]
                                  else "product_overlap", "to": doc["title"],
                                  "evidence": doc["association"] + f"，出处 [{number}]"})
            else:
                in_group = [doc for doc in docs if doc["kind"] in {"article", "paper"}
                            and doc["id"] in number_by_id]
                if in_group:
                    for doc in in_group[:3]:
                        number = number_by_id[doc["id"]]
                        parts.append(f"同一漏洞证据组中的研究/分析文章：{doc['title']}。[ {number} ]"
                                     .replace("[ ", "[").replace(" ]", "]"))
                        trace.append({"from": canonical, "via": "same_cve_group", "to": doc["title"],
                                      "evidence": f"同 CVE 归并，出处 [{number}]"})
                    parts.append("知识库中没有额外独立关联的论文或标准。")
                else:
                    parts.append("当前没有可确认与该漏洞直接相关的论文、标准或政策记录。")
        return {"answer": "\n\n".join(parts), "citations": citations,
                "trace": trace, "abstained": False, "canonical_id": canonical}

    def _answer_product(self, product: str, intents: set[str], session_id: str) -> dict[str, Any]:
        docs = self.db.search_vulnerability_documents(products=[product_key(product)], limit=1000)
        if not docs:
            return self._abstain(session_id, [f"未找到 {product} 的已入库漏洞证据。"])
        canonical_ids = list(dict.fromkeys(doc["canonical_id"] for doc in docs))[:10]
        if len(canonical_ids) == 1:
            return self._answer_vulnerability(canonical_ids[0], intents, session_id, product)
        self.sessions[session_id] = {"canonical": canonical_ids[0], "product": product}
        citations = [_citation(doc, i + 1) for i, doc in enumerate(docs[:10])]
        trace = [{"from": product, "via": "affects_product 反向检索", "to": item,
                  "evidence": "漏洞公告"} for item in canonical_ids]
        parts = [f"{product} 当前知识库涉及 {len(canonical_ids)} 个漏洞实体："]
        for i, doc in enumerate(docs[:10], 1):
            parts.append(f"- {doc['canonical_id']}：{doc['title']}。[{i}]")
        if "asset" in intents:
            for canonical in canonical_ids:
                impacts = [asset for asset in asset_impacts(self.db, canonical)
                           if asset["status"] == "affected"]
                if impacts:
                    parts.append(f"{canonical} 潜在影响本地资产：" + "、".join(x["name"] for x in impacts))
        knowledge = [doc for doc in self.db.documents(limit=200)
                     if doc["kind"] in {"paper", "standard", "policy", "article"}
                     and product.lower() in (doc["title"] + " " + doc["summary"]).lower()
                     and not any(vuln["id"] == doc["id"] for vuln in docs)]
        if knowledge or "paper" in intents or "standard" in intents or "policy" in intents:
            if knowledge:
                parts.append(f"{product} 相关知识底座文档：")
                for doc in knowledge[:4]:
                    number = len(citations) + 1
                    citations.append(_citation(doc, number))
                    parts.append(f"- [{doc['kind']}] {doc['title']}。[ {number} ]".replace("[ ", "[").replace(" ]", "]"))
                    trace.append({"from": product, "via": "product_overlap", "to": doc["title"],
                                  "evidence": f"知识文档涉及该产品，出处 [{number}]"})
            else:
                parts.append(f"知识库中暂无直接提及 {product} 的论文、标准或政策文档。")
        return {"answer": "\n".join(parts), "citations": citations,
                "trace": trace, "abstained": False}

    def _answer_portfolio(self, question: str, local_intents: set[str],
                          session_id: str, high_only: bool = False, *, product_filter: str = "") -> dict[str, Any]:
        """Analyst-style overview: topic filter, aggregated counts, top findings.

        The answer summarizes coverage first (how many records, which products,
        what was excluded and why), then lists a bounded top slice. Asset
        conclusions are aggregated once and only when the question itself asks
        about assets — a model planner must not expand the question's scope.
        """
        family = _portfolio_topic(question)
        if product_filter:
            family = {"label": product_filter, "products": [product_filter]}
        recent_first = any(term in question.casefold() for term in
                           ("最近", "最新", "近期", "recent", "latest"))
        family_products = {product_key(product) for product in family["products"]} if family else None
        pool = []
        while True:
            page = self.db.search_vulnerability_documents(
                products=sorted(family_products) if family_products else None,
                limit=500, offset=len(pool))
            pool.extend(page)
            if len(page) < 500:
                break
        # One cited document per entity. A recent request uses publication
        # date; other overviews continue to favour higher severity.
        best: dict[str, dict[str, Any]] = {}
        for doc in pool:
            rank = ((doc["published_at"] or "", doc["cvss"] or 0)
                    if recent_first else (doc["cvss"] or 0, doc["source_id"] == "nvd"))
            current = best.get(doc["canonical_id"])
            current_rank = (((current["published_at"] or "", current["cvss"] or 0)
                             if recent_first else (current["cvss"] or 0, current["source_id"] == "nvd"))
                            if current else None)
            if current is None or rank > current_rank:
                best[doc["canonical_id"]] = doc

        def passes_severity(doc: dict[str, Any]) -> bool:
            if not high_only:
                return True
            return bool({"HIGH", "CRITICAL"} & {str(doc["severity"]).upper()}) or (doc["cvss"] or 0) >= 7

        matched = sorted((doc for doc in best.values() if passes_severity(doc)),
                         key=(lambda doc: (doc["published_at"] or "", doc["cvss"] or 0)
                              if recent_first else (doc["cvss"] or 0, doc["published_at"] or "")),
                         reverse=True)
        below_threshold = len(best) - len(matched)
        if not matched:
            if best:
                scope = family["label"] if family else "当前筛选"
                return self._abstain(session_id, [
                    f"{scope}下没有{'高危级别' if high_only else ''}漏洞证据；"
                    f"共 {len(best)} 条记录未达到高危门槛，可去掉‘高危’限定后重问。"])
            return self._abstain(session_id, [
                "本地知识库没有漏洞证据。请先执行采集，或改用具体 CVE / 产品提问。"])

        model_ranked, ranking_error = False, None
        if len(matched) > 8 and not recent_first:
            matched, model_ranked, ranking_error = self._rank_with_model(question, matched)
        # Cover distinct products even if one feed floods the newest results.
        representatives, represented = [], set()
        for doc in matched:
            if doc["product"] not in represented:
                representatives.append(doc)
                represented.add(doc["product"])
        chosen_ids = {doc["id"] for doc in representatives}
        shown = (matched if recent_first else
                 representatives + [doc for doc in matched if doc["id"] not in chosen_ids])[:8]
        product_counts: dict[str, int] = {}
        for doc in matched:
            product_counts[doc["product"] or "产品待确认"] = \
                product_counts.get(doc["product"] or "产品待确认", 0) + 1
        citations = [_citation(doc, index + 1) for index, doc in enumerate(shown)]
        parts: list[str] = []
        scope_text = f"按主题「{family['label']}」过滤后，" if family else ""
        level_text = "高危" if high_only else ""
        sorted_products = sorted(product_counts.items(), key=lambda item: -item[1])
        coverage = "、".join(f"{product}（{count} 条）" for product, count in sorted_products[:6])
        if len(sorted_products) > 6:
            coverage += f"等 {len(sorted_products)} 个产品"
        parts.append(f"{scope_text}本地知识库共检索到 {len(matched)} 条{level_text}漏洞证据，"
                     f"覆盖 {len(product_counts)} 个产品：{coverage}。"
                     + ("以下按来源发布日期从新到旧列出；‘最近’只表示已入库记录的排序，不保证实时或指定时间窗口。"
                        if recent_first else "以下优先覆盖不同产品，再参考相关性、CVSS 与发布时间。")
                     + ("高危口径：来源标记 HIGH/CRITICAL，或 CVSS ≥ 7.0。" if high_only else ""))
        trace: list[dict[str, str]] = []
        lines: list[str] = []
        fix_available = 0
        for index, doc in enumerate(shown, 1):
            canonical = doc["canonical_id"]
            sentence = (f"- {canonical}（{doc['product'] or '产品待确认'}）："
                        f"{doc['severity'] or '级别未知'}，"
                        f"CVSS {doc['cvss'] if doc['cvss'] is not None else '未知'}")
            if recent_first:
                sentence += f"；来源发布日期 {str(doc.get('published_at') or '未知')[:10]}"
            if "fix" in local_intents:
                affected = doc.get("versions") or []
                if affected:
                    sentence += f"；公告影响范围 {', '.join(dict.fromkeys(affected[:2]))}"
                fixes = doc.get("fixed_versions") or []
                if fixes:
                    fix_available += 1
                    sentence += (f"；建议核对实际部署版本，并按该来源记录升级至"
                                 f" {', '.join(dict.fromkeys(fixes))} 后复测")
                else:
                    sentence += "；该来源未给出明确修复版本，需核对厂商公告后制定升级方案"
            excerpt = str(doc.get("summary") or doc.get("body") or doc["title"])
            snippet = excerpt[:160] + ("…" if len(excerpt) > 160 else "")
            lines.append(sentence + f"。[{index}]\n  来源摘要：{snippet} [{index}]")
            trace.append({"from": doc["product"] or "漏洞", "via": "topic_filter+severity",
                          "to": canonical, "evidence": f"公告出处 [{index}]"})
        header = "代表条目" if len(shown) < len(matched) else "全部条目"
        if len(shown) < len(matched):
            header += f"（仅列前 {len(shown)} 条，其余 {len(matched) - len(shown)} 条见知识库检索）"
        parts.append(header + "：\n" + "\n".join(lines))
        if "fix" in local_intents:
            parts.append(f"修复就绪度：本次展示的 {len(shown)} 条中 {fix_available}"
                         " 条已有明确修复版本证据，其余需按厂商公告核验。")
            parts.append("处置建议（需结合实际部署核验）：先按上面的公开影响范围核对产品和版本；"
                         "命中后查阅对应厂商公告，采用已确认的修复版本并复测。"
                         "没有明确修复版本的条目，不应从受影响范围上界推断补丁版本。")
        if "asset" in local_intents:
            asset_hits: dict[str, str] = {}
            for doc in matched:
                for asset in asset_impacts(self.db, doc["canonical_id"]):
                    if asset["status"] == "affected" and asset["name"] not in asset_hits:
                        asset_hits[asset["name"]] = doc["canonical_id"]
                        trace.append({"from": doc["canonical_id"], "via": "local_asset_version_match",
                                      "to": asset["name"], "evidence": "本地授权资产清单 + 公告版本范围"})
            if asset_hits:
                parts.append("登记资产聚合：版本规则命中的资产共 "
                             f"{len(asset_hits)} 台（" + "、".join(
                                 f"{name} ← {cve}" for name, cve in asset_hits.items())
                             + "）。资产与版本来自本地登记，实际暴露需人工核验。")
            else:
                parts.append("登记资产聚合：本次匹配范围内没有版本规则命中的资产；"
                             "未登记同产品的资产不计入结论。")
        notes: list[str] = []
        if family:
            universe = self.db.search_vulnerability_documents(limit=1000)
            outside = {}
            for doc in universe:
                if doc["product"] and product_key(doc["product"]) not in family_products:
                    outside[doc["product"]] = outside.get(doc["product"], 0) + 1
            excluded_names = "、".join(product for product, _ in
                                       sorted(outside.items(), key=lambda item: -item[1])[:3])
            excluded_total = len({doc["canonical_id"] for doc in universe
                                  if doc["product"] and product_key(doc["product"]) not in family_products})
            if excluded_total:
                notes.append(f"主题外另有 {excluded_total} 条公告（受影响产品如 {excluded_names}）"
                             "按问题主题排除，未计入上述统计")
            if below_threshold:
                notes.append(f"主题内另有 {below_threshold} 条因公开级别低于高危门槛未计入")
        elif below_threshold:
            notes.append(f"另有 {below_threshold} 条漏洞未达到高危门槛，未计入")
        if notes:
            parts.append("覆盖说明：" + "；".join(notes) + "。")
        dates = [str(doc["published_at"])[:10] for doc in matched if doc.get("published_at")]
        parts.append((f"匹配来源的最新发布日期：{max(dates)}。" if dates else "") +
                     "以上仅反映本地已采集证据，并非实时全网完整清单。")
        return {"answer": "\n\n".join(parts), "citations": citations,
                "trace": trace, "abstained": False, "_model_ranked": model_ranked,
                "_skip_evidence_selection": True, "_skip_evidence_synthesis": True,
                "_model_fallback_reason": ranking_error}

    def _rank_with_model(self, question: str, matched: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool, str | None]:
        """Optional model re-ranking of prefiltered candidates; local order on failure.

        The model only orders documents the SQL topic filter already selected;
        it cannot introduce CVEs, products or facts that are not in the list.
        """
        if not (self.allow_model and llm.enabled()) or len(matched) < 2:
            return matched, False, None
        candidates = [{"id": doc["id"], "canonical_id": doc["canonical_id"],
                       "product": doc["product"], "severity": doc["severity"],
                       "cvss": doc["cvss"],
                       "title": doc["title"][:140],
                       "summary": str(doc.get("summary") or "")[:500]} for doc in matched[:32]]
        try:
            ranked_ids = llm.rank_vulnerabilities(question, candidates, max_items=8)
        except Exception as exc:
            self.db.event(None, "证据排序代理", "候选相关性排序", "fallback", type(exc).__name__)
            return matched, False, type(exc).__name__
        by_id = {doc["id"]: doc for doc in matched}
        ranked = [by_id[doc_id] for doc_id in ranked_ids if doc_id in by_id]
        if not ranked:
            return matched, False, None
        remainder = [doc for doc in matched if doc not in ranked]
        self.db.event(None, "证据排序代理", "候选相关性排序", "ok",
                      f"model={llm.status()['model']}; ranked={len(ranked)}")
        return ranked + remainder, True, None

    def _answer_knowledge(self, question: str, intents: set[str], session_id: str,
                          semantic_terms: list[str] | None = None) -> dict[str, Any]:
        kind = next((key for key in ("paper", "standard", "policy") if key in intents), "")
        subjects = _knowledge_terms(question)
        if subjects:
            query = " ".join((semantic_terms or subjects)[:4])
            candidates = self.db.documents(query=query, kind=kind, limit=40)
            # FTS uses OR, so rank is not enough: all concrete user subjects
            # must occur in the cited text. Fall back to a bounded scan when
            # Chinese FTS tokenization misses an otherwise exact match.
            if not candidates:
                candidates = self.db.documents(kind=kind, limit=200)
            docs = [doc for doc in candidates if all(
                term.casefold() in " ".join(str(doc.get(field) or "") for field in
                                            ("title", "summary", "body", "product")).casefold()
                for term in subjects)][:8]
        elif kind:
            # A category-only request such as "有哪些政策法规" may list that
            # category. A concrete unsupported subject must never fall back.
            docs = self.db.documents(kind=kind, limit=8)
        else:
            docs = []
        if not docs:
            return self._abstain(session_id, ["知识库中没有足够证据回答这个问题。可先触发采集或改用具体 CVE / 产品名。"])
        citations = [_citation(doc, i + 1) for i, doc in enumerate(docs[:5])]
        parts = []
        for i, doc in enumerate(docs[:5], 1):
            excerpt = (doc["summary"] or doc["body"] or doc["title"])[:260]
            parts.append(f"{doc['title']}：{excerpt}。[ {i} ]".replace("[ ", "[").replace(" ]", "]"))
        return {"answer": "\n\n".join(parts), "citations": citations, "trace": [],
                "abstained": False}

    @staticmethod
    def _abstain(session_id: str, reasons: list[str]) -> dict[str, Any]:
        return {"answer": "\n".join(reasons), "citations": [], "trace": [],
                "abstained": True, "session_id": session_id}
