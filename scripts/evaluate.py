#!/usr/bin/env python3
"""Offline development rule checks; never an official contest accuracy score.

Run from any current directory with ``python3 scripts/evaluate.py``. This test
uses only bundled, manually curated public-source summaries and a temporary
SQLite database. It makes no network requests and scans no external assets.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sqlite3
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import Database  # noqa: E402
from app.intelligence import asset_impacts  # noqa: E402
from app.pipeline import Pipeline  # noqa: E402
from app.qa import AnswerEngine  # noqa: E402


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _percentile_nearest_rank(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return round(ordered[index], 2)


def _validate_gold(gold: dict[str, Any]) -> None:
    questions = gold.get("questions")
    if not isinstance(questions, list) or not questions:
        raise ValueError("eval_gold.json must contain a non-empty questions list")
    categories = Counter(item.get("category") for item in questions)
    if categories["basic"] < 3 or categories["multi_source"] < 2:
        raise ValueError("Gold set needs at least 3 basic and 2 multi-source questions")
    ids = [item.get("id") for item in questions]
    if len(ids) != len(set(ids)) or not all(ids):
        raise ValueError("Gold question IDs must be non-empty and unique")
    for item in questions:
        if not item.get("question") or not isinstance(item.get("must_include_all"), list):
            raise ValueError(f"Malformed gold case: {item.get('id')}")
        if not isinstance(item.get("required_source_ids"), list):
            raise ValueError(f"Missing required_source_ids: {item.get('id')}")
        if item.get("category") == "multi_source" and len(item["required_source_ids"]) < 2:
            raise ValueError(f"Multi-source case needs at least two sources: {item['id']}")
        facts = item.get("fact_evidence", [])
        if not isinstance(facts, list):
            raise ValueError(f"Malformed fact_evidence: {item['id']}")
        for fact in facts:
            if (not isinstance(fact, dict) or not fact.get("text")
                    or not isinstance(fact.get("source_ids"), list)
                    or not fact["source_ids"]
                    or not set(fact["source_ids"]) <= set(item["required_source_ids"])):
                raise ValueError(f"Malformed fact-level evidence rule: {item['id']}")


def _check_result(case: dict[str, Any], answer: dict[str, Any],
                  fixture_urls: dict[str, set[str]]) -> dict[str, Any]:
    answer_text = str(answer.get("answer") or "")
    citations = answer.get("citations") or []
    trace = answer.get("trace") or []
    required = list(case["required_source_ids"])
    cited_ids = {str(citation.get("source_id")) for citation in citations}
    missing_keywords = [word for word in case["must_include_all"]
                        if str(word).casefold() not in answer_text.casefold()]
    missing_sources = [source for source in required if source not in cited_ids]
    # A source merely appearing in a citation list is too weak. A selected
    # factual phrase must appear on the same answer line as the cited marker.
    # This is still a mechanical rule, not a semantic citation correctness test.
    missing_fact_evidence: list[dict[str, Any]] = []
    fact_rules = case.get("fact_evidence", [])
    for fact in fact_rules:
        markers = []
        for source in fact["source_ids"]:
            source_citations = [c for c in citations if c.get("source_id") == source]
            markers.append({f"[{c.get('number')}]" for c in source_citations})
        if not any(fact["text"].casefold() in line.casefold()
                   and all(any(marker in line for marker in options) for options in markers)
                   for line in answer_text.splitlines()):
            missing_fact_evidence.append(fact)
    seen_via = {item.get("via") for item in trace}
    missing_trace = [item for item in case.get("required_trace_via", []) if item not in seen_via]
    abstained_match = bool(answer.get("abstained")) == bool(case["expected_abstained"])
    canonical_match = ("expected_canonical_id" not in case or
                       answer.get("canonical_id") == case["expected_canonical_id"])
    empty_citation_on_abstain = not case["expected_abstained"] or not citations
    citation_urls_match_fixture = all(
        str(c.get("url") or "") in fixture_urls.get(str(c.get("source_id")), set())
        for c in citations
    )
    passed = (not missing_keywords and not missing_sources and not missing_fact_evidence
              and not missing_trace and abstained_match and canonical_match
              and empty_citation_on_abstain and citation_urls_match_fixture)
    return {
        "id": case["id"],
        "category": case["category"],
        "passed": passed,
        "missing_keywords": missing_keywords,
        "missing_sources": missing_sources,
        "missing_fact_evidence": missing_fact_evidence,
        "missing_trace_via": missing_trace,
        "abstained_match": abstained_match,
        "canonical_match": canonical_match,
        "empty_citation_on_abstain": empty_citation_on_abstain,
        "citation_urls_match_fixture": citation_urls_match_fixture,
        "required_citation_count": len(required),
        "matched_citation_count": len(required) - len(missing_sources),
        "required_fact_evidence_count": len(fact_rules),
        "matched_fact_evidence_count": len(fact_rules) - len(missing_fact_evidence),
        "cited_source_ids": sorted(cited_ids),
        "answer_excerpt": answer_text[:300] if not passed else None,
    }


def evaluate() -> dict[str, Any]:
    gold_path = PROJECT_ROOT / "data" / "eval_gold.json"
    records_path = PROJECT_ROOT / "data" / "demo_records.json"
    assets_path = PROJECT_ROOT / "data" / "demo_assets.json"
    gold = _load_json(gold_path)
    records = _load_json(records_path)
    assets = _load_json(assets_path)
    _validate_gold(gold)
    fixture_urls: dict[str, set[str]] = {}
    for record in records:
        fixture_urls.setdefault(str(record["source_id"]), set()).add(str(record["url"]))
    for case in gold["questions"]:
        unknown = set(case["required_source_ids"]) - set(fixture_urls)
        if unknown:
            raise ValueError(f"Unknown fixture source in {case['id']}: {sorted(unknown)}")

    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: Any) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    with tempfile.TemporaryDirectory(prefix="zhidun-eval-") as temporary:
        db = Database(Path(temporary) / "evaluation.sqlite3")
        pipeline = Pipeline(db, sources=[])
        first = pipeline.run_demo(records=records, assets=assets)
        after_first = db.stats()
        second = pipeline.run_demo(records=records, assets=assets)
        after_second = db.stats()

        expected_count = int(gold["expected_fixture_records"])
        check("离线样例完整导入", len(records) == expected_count
              and first["status"] == "success" and first["fetched"] == expected_count
              and first["inserted"] == expected_count and first["errors"] == 0
              and after_first["documents"] == expected_count,
              {"expected": expected_count, "first_run": first, "stored_documents": after_first["documents"]})
        check("重复采集幂等去重", second["status"] == "success"
              and second["fetched"] == expected_count and second["skipped"] == expected_count
              and second["inserted"] == 0 and second["updated"] == 0
              and second["errors"] == 0 and after_second["documents"] == after_first["documents"],
              {"second_run": second, "documents_before": after_first["documents"],
               "documents_after": after_second["documents"]})

        expected_vulns = int(gold["expected_unique_vulnerabilities"])
        check("漏洞实体数量", after_second["vulnerabilities"] == expected_vulns,
              {"expected": expected_vulns, "actual": after_second["vulnerabilities"]})
        group_gold = gold["expected_same_cve_group"]
        group = db.document_group(group_gold["canonical_id"])
        actual_sources = {item["source_id"] for item in group}
        check("同 CVE 多来源归一", len(group) == group_gold["document_count"]
              and set(group_gold["source_ids"]) <= actual_sources,
              {"canonical_id": group_gold["canonical_id"], "document_count": len(group),
               "source_ids": sorted(actual_sources)})

        asset_checks: list[dict[str, Any]] = []
        for expected in gold["expected_assets"]:
            impacts = asset_impacts(db, expected["canonical_id"])
            match = next((item for item in impacts if item["name"] == expected["asset_name"]), None)
            asset_checks.append({"canonical_id": expected["canonical_id"],
                                 "asset_name": expected["asset_name"],
                                 "expected": expected["status"],
                                 "actual": match["status"] if match else None,
                                 "passed": bool(match and match["status"] == expected["status"])})
        all_assets_marked_fictional = all(
            str(item.get("name") or "").startswith("演示-虚构-")
            and item.get("demo_only") is True for item in assets
        )
        check("虚构资产版本匹配", all(item["passed"] for item in asset_checks)
              and after_second["assets"] == len(assets)
              and all_assets_marked_fictional,
              {"matches": asset_checks, "all_marked_fictional": all_assets_marked_fictional})

        engine = AnswerEngine(db)
        sessions: dict[str, str] = {}
        qa_results: list[dict[str, Any]] = []
        latencies_ms: list[float] = []
        for case in gold["questions"]:
            session_key = case.get("session_key")
            session_id = sessions.get(session_key) if session_key else None
            started = time.perf_counter()
            try:
                answer = engine.ask(case["question"], session_id=session_id)
                elapsed_ms = (time.perf_counter() - started) * 1000
                result = _check_result(case, answer, fixture_urls)
                if session_key:
                    sessions[session_key] = answer["session_id"]
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - started) * 1000
                result = {"id": case["id"], "category": case["category"],
                          "passed": False, "error": f"{type(exc).__name__}: {exc}",
                          "required_citation_count": len(case["required_source_ids"]),
                          "matched_citation_count": 0,
                          "required_fact_evidence_count": len(case.get("fact_evidence", [])),
                          "matched_fact_evidence_count": 0}
            result["latency_ms"] = round(elapsed_ms, 2)
            qa_results.append(result)
            latencies_ms.append(elapsed_ms)

        qa_passed = sum(item["passed"] for item in qa_results)
        expected_citations = sum(item["required_citation_count"] for item in qa_results)
        hit_citations = sum(item["matched_citation_count"] for item in qa_results)
        multi_source_cases = [item for item in qa_results if item["category"] == "multi_source"]
        basic_cases = [item for item in qa_results if item["category"] == "basic"]
        required_facts = sum(item["required_fact_evidence_count"] for item in qa_results)
        matched_facts = sum(item["matched_fact_evidence_count"] for item in qa_results)
        check("固定问答规则验收", qa_passed == len(qa_results),
              {"passed": qa_passed, "total": len(qa_results),
               "failed_ids": [item["id"] for item in qa_results if not item["passed"]]})
        context_case = next((item for item in gold["questions"]
                             if item.get("requires_session_context")), None)
        if context_case:
            fresh_answer = engine.ask(context_case["question"], session_id=None)
            check("指代追问依赖既有会话上下文",
                  fresh_answer.get("canonical_id") != context_case["expected_canonical_id"]
                  and any(item["id"] == context_case["id"] and item["passed"]
                          for item in qa_results),
                  {"question_id": context_case["id"],
                   "fresh_session_canonical_id": fresh_answer.get("canonical_id"),
                   "continued_session_expected_canonical_id": context_case["expected_canonical_id"],
                   "note": "只验证该条指代式开发样例，不代表一般多轮理解能力"})
        latency = db.collection_latency_stats()
        check("离线快照时间差统计管道可用", latency["demo_snapshot"]["samples"] == len(records)
              and latency["live"]["samples"] == 0
              and (latency["demo_snapshot"]["p50_hours"] or 0) > 0,
              {"latency_stats": latency,
               "note": "多数样例只有日期没有时分秒；这个时间差不代表线上发现或采集时效"})

    replay_dedup_rate = _rate(second["skipped"], second["fetched"])
    report = {
        "evaluation_type": "development_fixture_self_test",
        "official_contest_score": None,
        "official_metrics": {"online_monitoring_latency_hours": None,
                             "enrichment_precision": None, "enrichment_recall": None,
                             "qa_accuracy": None, "qa_multihop_accuracy": None},
        "disclaimer": "人工选定的离线开发样例与规则同源，规则通过率不是问答准确率；非独立留出集、人工语义盲评、真实线上时效或官方评分，不能据此宣称达到赛题 95% 门槛。",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset_id": gold["dataset_id"],
        "runtime": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                    "platform": platform.platform()},
        "dataset_sha256": {"eval_gold": _sha256(gold_path),
                           "demo_records": _sha256(records_path),
                           "demo_assets": _sha256(assets_path)},
        "sample_counts": {"records": len(records), "assets": len(assets),
                          "questions": len(qa_results), "basic_questions": len(basic_cases),
                          "multi_source_questions": len(multi_source_cases),
                          "abstention_questions": sum(x["category"] == "safety_abstention"
                                                     for x in qa_results)},
        "ingestion": {"first_run": first, "replay_run": second,
                      "stored_documents_after_replay": after_second["documents"],
                      "unique_vulnerability_entities": after_second["vulnerabilities"],
                      "replay_dedup_rate": replay_dedup_rate,
                      "replay_dedup_definition": "第二次原样导入的 skipped / fetched；不代表在线跨源去重准确率",
                      "collection_latency": latency},
        "qa_metrics": {"passed": qa_passed, "total": len(qa_results),
                       "rule_case_pass_rate": _rate(qa_passed, len(qa_results)),
                       "basic_rule_pass_rate": _rate(sum(x["passed"] for x in basic_cases), len(basic_cases)),
                       "multi_source_rule_pass_rate": _rate(sum(x["passed"] for x in multi_source_cases),
                                                            len(multi_source_cases)),
                       "required_citation_presence_rate": _rate(hit_citations, expected_citations),
                       "fact_line_citation_marker_rate": _rate(matched_facts, required_facts),
                       "rule_method": "预设词、实体、轨迹、来源 URL 和同一答案行的事实引用标记；不判定语义正确性、引用内容支持性或多跳推理泛化",
                       "multi_source_scope": "3 题均围绕同一 Ollama CVE；双来源归并不等于跨独立案例多跳推理",
                       "response_ms_p50": _percentile_nearest_rank(latencies_ms, 0.50),
                       "response_ms_p95": _percentile_nearest_rank(latencies_ms, 0.95),
                       "latency_method": "perf_counter 包围单次 in-process AnswerEngine.ask；最近秩百分位；导入完成后固定题、单用户、本地离线、无 HTTP/联网/LLM，不能与决赛 ≤5 秒档直接比较"},
        "checks": checks,
        "question_results": qa_results,
        "passed": all(item["passed"] for item in checks),
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="输出机器可读 JSON 报告")
    args = parser.parse_args()
    try:
        report = evaluate()
    except Exception as exc:
        print(f"评测无法运行：{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        counts = report["sample_counts"]
        ingest = report["ingestion"]
        qa = report["qa_metrics"]
        print("知盾离线开发样例自测（非官方评分）")
        print(report["disclaimer"])
        print(f"样本：{counts['records']} 条情报、{counts['assets']} 个虚构资产、"
              f"{counts['questions']} 道题（基础 {counts['basic_questions']}，"
              f"双源/关联 {counts['multi_source_questions']}，"
              f"拒答 {counts['abstention_questions']}）")
        print(f"采集：首轮入库 {ingest['first_run']['inserted']}，重放跳过 "
              f"{ingest['replay_run']['skipped']}，重放去重率 {ingest['replay_dedup_rate']:.1%}，"
              f"唯一漏洞实体 {ingest['unique_vulnerability_entities']}")
        print(f"问答：固定规则通过 {qa['passed']}/{qa['total']} "
              f"({qa['rule_case_pass_rate']:.1%})，必需来源引用存在率 "
              f"{qa['required_citation_presence_rate']:.1%}，事实同行引用标记率 "
              f"{qa['fact_line_citation_marker_rate']:.1%}")
        print(f"响应：p50 {qa['response_ms_p50']:.2f} ms，"
              f"p95 {qa['response_ms_p95']:.2f} ms（本地离线，最近秩法）")
        for check in report["checks"]:
            print(f"{'通过' if check['passed'] else '失败'}：{check['name']}")
        for item in report["question_results"]:
            if not item["passed"]:
                print(f"失败题目 {item['id']}：{json.dumps(item, ensure_ascii=False)}")
        print("结果：" + ("全部通过" if report["passed"] else "存在失败项"))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
