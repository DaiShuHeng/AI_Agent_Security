"""Domain normalization, provenance-aware enrichment and local asset matching."""

from __future__ import annotations

import re
from typing import Any

from .db import Database


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.I)
AI_TERMS = (
    "ollama", "vllm", "triton inference", "langchain", "langflow", "llama-cpp",
    "huggingface", "transformers", "pytorch", "tensorflow", "openai", "mcp",
    "model context protocol", "agentic", "llm", "large language model", "genai",
    "generative ai", "prompt injection", "model poisoning", "rag", "人工智能",
    "大模型", "智能体", "提示词注入", "模型投毒", "推理框架", "模型安全",
    "llama", "mlflow", "litellm", "open webui", "llamaindex", "autogen",
    "crewai", "smolagents", "chatgpt", "copilot", "deepseek", "qwen",
    "ai agent", "ai model", "ai system", "inference server", "大语言模型",
    "inference framework", "inference engine", "llm inference", "serving framework",
    "ai application", "mcp server",
)
SOURCE_CONFIDENCE = {
    "nvd": 0.96, "github_advisories": 0.92, "cisa_kev": 0.98,
    "paper": 0.72, "standard": 0.94, "policy": 0.94,
    "vendor": 0.86, "community": 0.65, "blog": 0.62,
    "demo": 0.91,
}
PRODUCT_ALIASES = {
    "ollama": ("ollama",),
    "llama-cpp-python": ("llama-cpp-python", "llama_cpp_python", "llama cpp python"),
    "langflow": ("langflow",),
    "langchain": ("langchain",),
    "vllm": ("vllm", "vllm-project"),
    "triton": ("triton inference server", "nvidia triton"),
    "transformers": ("transformers", "huggingface transformers"),
    "pytorch": ("pytorch", "torch"),
}


def product_key(value: str) -> str:
    value = value.lower().strip()
    for canonical, aliases in PRODUCT_ALIASES.items():
        if value == canonical or value in aliases:
            return canonical
    return value.replace("_", "-")


def infer_product(text: str) -> str:
    lower = text.lower()
    for canonical, aliases in PRODUCT_ALIASES.items():
        if any(alias in lower for alias in aliases):
            return canonical
    return ""


def ai_relevance(record: dict[str, Any]) -> float:
    if record.get("kind") in {"paper", "standard", "policy"}:
        return 1.0
    text = " ".join(str(record.get(key, "")) for key in ("title", "summary", "body", "product")).lower()
    matches = sum(term in text for term in AI_TERMS)
    if product_key(str(record.get("product") or "")) in PRODUCT_ALIASES:
        matches += 2
    return min(1.0, matches / 3.0)


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    item = dict(record)
    ids = item.get("identifiers") or []
    if isinstance(ids, dict):
        ids = list(ids.values())
    ids = [str(value).upper() for value in ids if value]
    text = " ".join([str(item.get("external_id") or ""), str(item.get("title") or ""),
                     str(item.get("summary") or ""), " ".join(ids)])
    cves = list(dict.fromkeys(match.upper() for match in CVE_RE.findall(text)))
    ghsas = list(dict.fromkeys(match.upper() for match in GHSA_RE.findall(text)))
    item["identifiers"] = list(dict.fromkeys(cves + ghsas + ids))
    item["canonical_id"] = cves[0] if cves else (
        ghsas[0] if ghsas else str(item.get("external_id") or item.get("url") or ""))
    item["kind"] = str(item.get("kind") or "article")
    item["product"] = product_key(str(item.get("product") or infer_product(text)))
    item["ai_score"] = ai_relevance(item)
    item["versions"] = _list_of_strings(item.get("versions"))
    item["fixed_versions"] = _list_of_strings(item.get("fixed_versions"))
    item["refs"] = _list_of_strings(item.get("refs"))
    item["cvss"] = _valid_cvss(item.get("cvss"))
    item["source_category"] = str(item.get("source_category") or "community")
    return item


def _list_of_strings(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        value = [value]
    return [str(v).strip() for v in value if str(v).strip()]


def _valid_cvss(value: Any) -> float | None:
    try:
        number = float(value)
        return round(number, 1) if 0 <= number <= 10 else None
    except (TypeError, ValueError):
        return None


def record_claims(db: Database, document_id: int, record: dict[str, Any]) -> dict[str, int]:
    """Store literal claims only. Inferred associations use a lower confidence."""
    canonical = record["canonical_id"]
    source = record.get("source_category", "community")
    confidence = SOURCE_CONFIDENCE.get(source, 0.65)
    evidence = (record.get("summary") or record.get("title") or "")[:500]
    claims: list[tuple[str, str, str, float]] = []
    product = record.get("product")
    if product:
        claims.append((canonical, "affects_product", product, confidence))
    if record.get("cvss") is not None:
        claims.append((canonical, "cvss", str(record["cvss"]), confidence))
    if record.get("severity"):
        claims.append((canonical, "severity", str(record["severity"]), confidence))
    for version in record.get("versions", []):
        claims.append((canonical, "affected_version", version, confidence))
    for version in record.get("fixed_versions", []):
        claims.append((canonical, "fixed_version", version, confidence))
    for ref in record.get("refs", []):
        if ref.startswith("https://"):
            pred = "poc_reference" if re.search(r"(?:poc|proof.of.concept|exploit)", ref, re.I) else "reference"
            claims.append((canonical, pred, ref, max(0.4, confidence - 0.12)))
    for ref in record.get("raw", {}).get("references", []):
        if not isinstance(ref, dict):
            continue
        ref_url = str(ref.get("url") or "")
        tags = {str(tag).casefold() for tag in (ref.get("tags") or [])}
        if ref_url.startswith("https://") and "exploit" in tags:
            claims.append((canonical, "poc_reference", ref_url, max(0.4, confidence - 0.08)))
        if ref_url.startswith("https://") and "patch" in tags:
            claims.append((canonical, "patch_reference", ref_url, confidence))
    for identifier in record.get("identifiers", []):
        if identifier != canonical:
            claims.append((canonical, "alias", identifier, confidence))
    if record.get("raw", {}).get("known_exploited") is True:
        claims.append((canonical, "known_exploited", "true", confidence))
    if record["kind"] in {"paper", "article", "standard", "policy"} and product:
        claims.append((product, "related_" + record["kind"], record.get("url", ""),
                       max(0.4, confidence - 0.16)))
    for cve in CVE_RE.findall(" ".join([record.get("title", ""), record.get("summary", ""),
                                          record.get("body", "")])):
        if cve.upper() != canonical:
            claims.append((cve.upper(), "mentioned_in", record.get("url", ""), 0.70))
    for subject, predicate, obj, score in claims:
        db.add_claim(subject, predicate, obj, document_id, evidence, score)
    return {"total": len(claims),
            "cross_mentions": sum(1 for c in claims if c[1] == "mentioned_in")}


def related_knowledge(db: Database, canonical_id: str, products: list[str],
                      limit: int = 4) -> list[dict[str, Any]]:
    """Automatic association reasoning across documents.

    Priority 1: knowledge documents that explicitly cite the identifier
    (mentioned_in claims). Priority 2: knowledge documents overlapping on the
    affected product, clearly weaker because the source never names the CVE.
    """
    related = db.related_documents(canonical_id, limit)
    for item in related:
        item["association"] = "来源原文提及该漏洞标识"
    seen_urls = {item["url"] for item in related}
    if products:
        for doc in db.documents(limit=200):
            if doc["kind"] not in {"paper", "standard", "policy", "article"} or doc["url"] in seen_urls:
                continue
            if not any(product and product.lower() in (doc["title"] + doc["summary"]).lower()
                       for product in products):
                continue
            doc["association"] = "产品重合推断：文档未直接提及该漏洞标识"
            related.append(doc)
            seen_urls.add(doc["url"])
            if len(related) >= limit:
                break
    return related[:limit]


def _numeric_version(value: str) -> tuple[int, ...] | None:
    if not re.fullmatch(r"\d+(?:\.\d+)*", value.strip()):
        return None
    return tuple(int(part) for part in value.split("."))


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    n = max(len(left), len(right))
    a = left + (0,) * (n - len(left))
    b = right + (0,) * (n - len(right))
    return (a > b) - (a < b)


def match_version(version: str, ranges: list[str], fixed: list[str]) -> str:
    """Conservative matcher: unknown means no assertion of impact."""
    current = _numeric_version(version)
    if current is None:
        return "unknown"
    if ranges:
        # A comma-joined interval is AND. Distinct interval strings are OR.
        # Some feeds split one lower and one upper bound into two list items;
        # combine that unambiguous pair as one interval.
        normalized = [item.lower().replace("through", "<=").replace("before", "<")
                      for item in ranges]
        single_bounds = [re.fullmatch(r"\s*(<=|>=|<|>)\s*v?\d+(?:\.\d+)*\s*", item)
                         for item in normalized]
        if (len(normalized) == 2 and all(single_bounds)
                and any(item.lstrip().startswith((">", ">=")) for item in normalized)
                and any(item.lstrip().startswith(("<", "<=")) for item in normalized)):
            normalized = [", ".join(normalized)]
        outcomes = []
        for item in normalized:
            checks = []
            for expression in item.split(","):
                expression = expression.strip()
                match = re.fullmatch(r"(<=|>=|<|>|==|=)?\s*v?(\d+(?:\.\d+)*)", expression)
                if not match:
                    checks = []
                    break
                op, boundary_raw = match.groups()
                op = op or "=="
                boundary = _numeric_version(boundary_raw)
                if boundary is None:
                    checks = []
                    break
                cmp = _compare(current, boundary)
                checks.append({"<": cmp < 0, "<=": cmp <= 0, ">": cmp > 0,
                               ">=": cmp >= 0, "=": cmp == 0, "==": cmp == 0}[op])
            outcomes.append(all(checks) if checks else None)
        if any(result is True for result in outcomes):
            return "affected"
        if outcomes and all(result is False for result in outcomes):
            return "not_affected"
        return "unknown"
    if fixed:
        parsed = [_numeric_version(v) for v in fixed]
        parsed = [v for v in parsed if v is not None]
        if parsed:
            return "affected" if _compare(current, min(parsed)) < 0 else "not_affected"
    return "unknown"


def asset_impacts(db: Database, canonical_id: str) -> list[dict[str, Any]]:
    documents = db.document_group(canonical_id)
    impacts = []
    for asset in db.assets():
        related = [doc for doc in documents if product_key(doc["product"]) == product_key(asset["product"])]
        if not related:
            continue
        results = [(doc, match_version(asset["version"], doc["versions"], doc["fixed_versions"]))
                   for doc in related]
        status = "affected" if any(s == "affected" for _, s in results) else (
            "not_affected" if results and all(s == "not_affected" for _, s in results) else "unknown")
        scores = [doc["cvss"] for doc in related if doc["cvss"] is not None]
        cvss = max(scores) if scores else None
        exposure = {"internet": 1.3, "internal": 1.0, "isolated": 0.7}[asset["exposure"]]
        priority = round(cvss * exposure * (0.6 + asset["criticality"] / 10), 1) if cvss is not None else None
        impacts.append({**asset, "status": status, "priority": priority,
                        "priority_basis": "CVSS × 暴露系数 × (0.6 + 关键度/10)" if cvss is not None else "CVSS 缺失，待评估",
                        "evidence": [{"title": doc["title"], "url": doc["url"], "source_id": doc["source_id"]}
                                     for doc, result in results if result == status][:3]})
    return sorted(impacts, key=lambda item: (item["status"] != "affected", -(item["priority"] or -1)))
