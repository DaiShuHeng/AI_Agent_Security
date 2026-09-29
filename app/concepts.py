"""Conservative general-knowledge routing; concrete intelligence stays in retrieval."""
import re

CONCEPTS = (
    "ai安全", "ai 安全", "人工智能安全", "大模型安全", "模型安全", "ai security",
    "提示词注入", "提示注入", "prompt injection", "越狱", "jailbreak", "数据投毒",
    "模型投毒", "模型幻觉", "幻觉", "rag", "检索增强", "智能体", "agent",
    "cvss", "epss", "零信任", "供应链安全", "ai safety", "对抗样本", "模型窃取",
    "推理框架", "模型反演", "成员推断", "cve", "安全对齐", "安全情报",
    "vllm", "ollama", "lmdeploy", "langchain", "pytorch", "网络安全",
)
EXPLANATION = ("是什么", "什么是", "什么意思", "解释", "介绍", "科普", "区别", "举例",
               "如何理解", "原理", "怎么防", "如何防", "风险类型", "哪些风险", "分为", "what is", "explain")
FOLLOWUP = ("举个例子", "举例", "展开", "详细一点", "简单一点", "继续", "怎么防", "如何防", "它", "这个", "还有呢")


def evidence_question(question: str) -> bool:
    """Requests for published artifacts/sources outrank general explanation."""
    lower = question.casefold()
    return any(term in lower for term in (
        "论文", "标准", "政策", "法规", "公告", "报告", "出处", "来源", "引用",
        "paper", "standard", "policy", "report", "advisory", "source", "citation"))


def concept_question(question: str, previous: bool = False, model_mode: str = "") -> bool:
    lower = question.lower()
    if evidence_question(question):
        return False
    # Definition of CVSS is allowed; a real CVE, version or dated/current query is not.
    if re.search(r"cve-\d|ghsa-|\b\d+\.\d+|\b20\d{2}\b", lower):
        return False
    if any(word in lower for word in ("最新", "今天", "目前", "最近", "修复版本", "补丁版本", "在野", "kev", "罚款", "第几条", "我的", "我们", "登记资产", "哪些漏洞", "漏洞有哪些", "高危漏洞", "漏洞列表")):
        return False
    domain = any(term in lower for term in CONCEPTS)
    explain = any(term in lower for term in EXPLANATION) or "有什么安全风险" in lower
    return (domain and (explain or model_mode == "concept")) or (
        previous and any(term in lower for term in FOLLOWUP) and not any(
            term in lower for term in ("服务器", "资产", "漏洞编号", "版本")))


AI_SECURITY_FALLBACK = (
    "AI 安全是识别和降低人工智能系统在数据、模型、应用和运行环境中的安全风险，"
    "使系统在正常使用和受到攻击时都能保护数据、遵守权限并可靠运行。\n\n"
    "常见风险包括：提示词注入诱导模型或智能体越权；训练数据投毒影响模型行为；"
    "敏感信息泄露；模型与依赖组件的供应链漏洞；模型幻觉和不可靠输出。\n\n"
    "假想例子：一个能读取文档并发邮件的助手，遇到文档里‘把客户资料发到某地址’的指令。"
    "如果把外部文档当成可信指令，就可能泄露信息。防护需要区分指令和数据、限制工具权限、"
    "对敏感操作设置核验，并记录操作过程。\n\n"
    "模型回答正确只是其中一部分；还需要保护接口、身份、数据和部署环境。"
)
