"""Bounded, read-only connectors for public AI security intelligence feeds.

All adapters return the same JSON-serializable record shape. Source text is
untrusted evidence: this module never follows links found inside records,
executes proof-of-concept code, or probes an internet asset.

Official formats:
* NVD CVE API 2.0: https://nvd.nist.gov/developers/vulnerabilities
* GitHub global advisories: https://docs.github.com/en/rest/security-advisories/global-advisories
* CISA KEV schema: https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json
"""

from __future__ import annotations

import ipaddress
import hashlib
import json
import logging
import math
import os
import re
import ssl
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from xml.etree import ElementTree

from .intelligence import match_version


LOG = logging.getLogger(__name__)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_URL = "https://api.github.com/advisories"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://api.osv.dev/v1/query"
EPSS_URL = "https://api.first.org/data/v1/epss"
# OSV ecosystem names are case-sensitive in the query API.
OSV_ECOSYSTEMS = {"pypi": "PyPI", "go": "Go", "npm": "npm", "maven": "Maven",
                  "crates.io": "crates.io", "rubygems": "RubyGems",
                  "packagist": "Packagist", "nuget": "NuGet"}
DEFAULT_OSV_PACKAGES = (
    "pypi:langchain", "pypi:langflow", "pypi:llama-cpp-python", "pypi:gradio",
    "pypi:vllm", "pypi:litellm", "pypi:mlflow", "pypi:transformers",
    "pypi:smolagents", "pypi:llama-index", "pypi:autogen", "pypi:crewai",
    "go:github.com/ollama/ollama", "npm:langchain",
)
DEFAULT_KEYWORDS = (
    "ollama", "vllm", "langchain", "mlflow", "litellm", "open webui",
    "llama.cpp", "hugging face", "triton inference", "ray serve",
    "large language model", "generative ai", "prompt injection",
    "artificial intelligence", "machine learning", "模型投毒", "提示词注入",
    "人工智能", "大语言模型", "智能体", "模型安全",
)
NVD_DEFAULT_QUERIES = ("ollama", "vllm", "langchain", "mlflow")
MAX_RESULTS = 1000
MAX_NVD_QUERIES = 8
MAX_NVD_PAGES_PER_TERM = 3
MAX_GITHUB_PAGES = 5
MAX_OSV_PAGES_PER_PACKAGE = 10
HTTP_TIMEOUT_SECONDS = 12
JSON_RESPONSE_BYTES = 8 * 1024 * 1024
XML_RESPONSE_BYTES = 4 * 1024 * 1024
_IDENTIFIER = re.compile(r"\b(?:CVE-\d{4}-\d{4,19}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", re.I)
_NVD_REQUESTS: deque[float] = deque()
_NVD_LOCK = threading.Lock()


class ConnectorError(RuntimeError):
    """A source could not be fetched or parsed; the scheduler may retry it."""


def _validated_url(url: str) -> str:
    """Reject local URLs, userinfo, and non-HTTPS redirects from source config."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        raise ConnectorError(f"Invalid source URL: {exc}") from exc
    if parsed.scheme.lower() != "https" or not host or parsed.username or parsed.password:
        raise ConnectorError("Source URL must be a public HTTPS URL without credentials")
    if port not in (None, 443) or host.lower() in {"localhost", "localhost.localdomain"}:
        raise ConnectorError("Source URL must use the public HTTPS port")
    try:
        if not ipaddress.ip_address(host).is_global:
            raise ConnectorError("Private or loopback source addresses are not allowed")
    except ValueError:
        if host.lower().endswith((".local", ".internal", ".localhost")):
            raise ConnectorError("Local source hostnames are not allowed")
    return url


def _safe_reference(candidate: Any, *, base: str | None = None) -> str:
    """Keep untrusted record links as display-only public HTTPS references."""
    if not isinstance(candidate, str) or not candidate.strip():
        return ""
    resolved = urljoin(base, candidate.strip()) if base else candidate.strip()
    try:
        return _validated_url(resolved)
    except ConnectorError:
        return ""


class _SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> Request | None:
        _validated_url(newurl)
        credential_headers = {name.casefold() for name, _ in req.header_items()}
        if ({"authorization", "apikey"} & credential_headers and
                urlparse(req.full_url).hostname != urlparse(newurl).hostname):
            raise ConnectorError("Authenticated source may not redirect to another host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _tls_context() -> ssl.SSLContext:
    """Use a verified CA bundle on Python builds lacking system OpenSSL roots."""
    try:
        import certifi  # type: ignore[import-not-found]
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def _http_get(url: str, *, accept: str, max_bytes: int,
              headers: dict[str, str] | None = None) -> tuple[bytes, dict[str, str]]:
    """Small GET seam for test monkeypatching; never reads beyond max_bytes."""
    _validated_url(url)
    request_headers = {
        "Accept": accept,
        "User-Agent": "Zhidun-AI-Security-Intelligence/1.0 (+public-feed-reader)",
    }
    request_headers.update(headers or {})
    req = Request(url, headers=request_headers, method="GET")
    try:
        with build_opener(_SafeRedirect(), HTTPSHandler(context=_tls_context())).open(
                req, timeout=HTTP_TIMEOUT_SECONDS) as response:
            length = response.headers.get("Content-Length")
            if length:
                try:
                    if int(length) > max_bytes:
                        raise ConnectorError(f"Response exceeds {max_bytes} bytes: {url}")
                except ValueError:
                    LOG.warning("Source %s supplied malformed Content-Length %r", url, length)
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ConnectorError(f"Response exceeds {max_bytes} bytes: {url}")
            return data, dict(response.headers.items())
    except HTTPError as exc:
        retry = exc.headers.get("Retry-After") if exc.headers else None
        detail = f"HTTP {exc.code} from {url}"
        if retry:
            detail += f" (Retry-After: {retry})"
        raise ConnectorError(detail) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ConnectorError(f"Could not fetch {url}: {exc}") from exc


def _get_json(url: str, *, max_bytes: int = JSON_RESPONSE_BYTES,
              headers: dict[str, str] | None = None) -> tuple[Any, dict[str, str]]:
    data, response_headers = _http_get(url, accept="application/json", max_bytes=max_bytes,
                                       headers=headers)
    try:
        return json.loads(data), response_headers
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorError(f"Invalid JSON from {url}: {exc}") from exc


def _post_json(url: str, payload: dict[str, Any], *, max_bytes: int = JSON_RESPONSE_BYTES,
               headers: dict[str, str] | None = None) -> tuple[Any, dict[str, str]]:
    """Small POST seam for test monkeypatching; only public HTTPS endpoints."""
    _validated_url(url)
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Zhidun-AI-Security-Intelligence/1.0 (+public-feed-reader)",
    }
    request_headers.update(headers or {})
    body = json.dumps(payload).encode("utf-8")
    request = Request(url, data=body, headers=request_headers, method="POST")
    try:
        with build_opener(_SafeRedirect(), HTTPSHandler(context=_tls_context())).open(
                request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ConnectorError(f"Response exceeds {max_bytes} bytes: {url}")
            try:
                return json.loads(data), dict(response.headers.items())
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ConnectorError(f"Invalid JSON from {url}: {exc}") from exc
    except HTTPError as exc:
        raise ConnectorError(f"HTTP {exc.code} from {url}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ConnectorError(f"Could not post {url}: {exc}") from exc


def _utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(value: str | None) -> str | None:
    parsed = _utc(value)
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z") if parsed else None


def _since(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = _utc(value)
    if parsed is None:
        raise ValueError(f"Invalid since timestamp: {value!r}")
    return parsed


def _query_url(base: str, **params: Any) -> str:
    parsed = urlparse(base)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update({key: str(value) for key, value in params.items() if value is not None})
    return urlunparse(parsed._replace(query=urlencode(query)))


def _keywords(source: dict[str, Any]) -> list[str]:
    raw = source.get("keywords")
    if isinstance(raw, str):
        terms = [part.strip() for part in re.split(r"[,;，；\n]", raw)]
    elif isinstance(raw, (list, tuple)):
        terms = [str(part).strip() for part in raw]
    elif raw is None:
        terms = list(DEFAULT_KEYWORDS)
    else:
        raise ValueError("source.keywords must be a list of strings or comma-separated string")
    return list(dict.fromkeys(term for term in terms if term))


def _matches(text: str, terms: list[str]) -> bool:
    lowered = text.casefold()
    for term in terms:
        needle = term.casefold()
        if re.search(r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])", lowered):
            return True
    return False


def _identifiers(*texts: str) -> list[str]:
    return list(dict.fromkeys(match.upper() for text in texts for match in _IDENTIFIER.findall(text or "")))


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _record(source: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return {
        "external_id": fields.get("external_id"),
        "title": fields.get("title") or "",
        "summary": fields.get("summary") or "",
        "body": fields.get("body") or "",
        "url": fields.get("url") or "",
        "published_at": fields.get("published_at"),
        "updated_at": fields.get("updated_at"),
        "source_id": source["id"],
        "source_category": source.get("category") or source["type"],
        "kind": fields.get("kind") or "article",
        "identifiers": fields.get("identifiers") or [],
        "product": fields.get("product") or "",
        "cvss": fields.get("cvss"),
        "severity": fields.get("severity") or "",
        "versions": fields.get("versions") or [],
        "fixed_versions": fields.get("fixed_versions") or [],
        "refs": fields.get("refs") or [],
        "raw": fields.get("raw") or {},
    }


def _cpe_parts(criteria: str) -> list[str]:
    """Split CPE 2.3 components without treating escaped colons as separators."""
    parts: list[str] = []
    part: list[str] = []
    escaped = False
    for char in criteria:
        if char == ":" and not escaped:
            parts.append("".join(part))
            part = []
        else:
            part.append(char)
        escaped = char == "\\" and not escaped
    parts.append("".join(part))
    return parts


def _nvd_affected(cve: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Keep each CPE product paired with only its own version ranges."""
    products: dict[str, list[str]] = {}

    def walk(node: Any, conditional: bool = False) -> None:
        if isinstance(node, list):
            for child in node:
                walk(child, conditional)
        elif isinstance(node, dict):
            if node.get("negate"):
                return
            # AND configurations need environmental facts beyond a product's
            # version. Keep the product but make asset impact "unknown".
            conditional = conditional or str(node.get("operator") or "OR").upper() == "AND"
            for match in node.get("cpeMatch", []):
                if not isinstance(match, dict) or not match.get("vulnerable", False):
                    continue
                parts = _cpe_parts(str(match.get("criteria", "")))
                if len(parts) <= 5:
                    continue
                product = parts[4].replace("\\:", ":").replace("_", " ").strip()
                if not product or product in {"*", "-"}:
                    continue
                ranges = products.setdefault(product, [])
                if conditional:
                    continue
                bounds = []
                for key, marker in (("versionStartIncluding", ">="),
                                    ("versionStartExcluding", ">"),
                                    ("versionEndIncluding", "<="),
                                    ("versionEndExcluding", "<")):
                    if match.get(key):
                        bounds.append(marker + str(match[key]))
                if bounds:
                    ranges.append(", ".join(bounds))
                elif parts[5] not in {"*", "-", ""}:
                    ranges.append("==" + parts[5])
            for key in ("nodes", "children"):
                walk(node.get(key, []), conditional)

    walk(cve.get("configurations", []))
    # NVD's newer API can expose CNA affectedData before CPE enrichment exists.
    # Only simple, explicitly "affected" ranges are promoted to version claims.
    if not products or not any(products.values()):
        cna_products: dict[str, list[str]] = {}
        for contribution in cve.get("affected", []):
            if not isinstance(contribution, dict):
                continue
            for entry in contribution.get("affectedData", []):
                if not isinstance(entry, dict):
                    continue
                product = str(entry.get("packageName") or entry.get("product") or "").strip()
                if not product:
                    continue
                ranges = cna_products.setdefault(product, [])
                for version in entry.get("versions", []):
                    if (not isinstance(version, dict) or version.get("status") != "affected"
                            or version.get("changes")):
                        continue
                    lower = str(version.get("version") or "").strip()
                    if not lower or lower == "*":
                        continue
                    if version.get("lessThan"):
                        ranges.append(f">={lower}, <{version['lessThan']}")
                    elif version.get("lessThanOrEqual"):
                        ranges.append(f">={lower}, <={version['lessThanOrEqual']}")
                    else:
                        ranges.append("==" + lower)
        if cna_products:
            products = cna_products
    return [(product, _unique(ranges)) for product, ranges in products.items()] or [("", [])]


def _nvd_metric(cve: dict[str, Any]) -> tuple[float | None, str]:
    metrics = cve.get("metrics") or {}
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(name) or []
        if not entries:
            continue
        preferred = next((item for item in entries if item.get("type") == "Primary"), entries[0])
        score_data = preferred.get("cvssData") or {}
        score = score_data.get("baseScore")
        severity = preferred.get("baseSeverity") or score_data.get("baseSeverity") or ""
        if score is not None:
            return float(score), str(severity).upper()
    return None, ""


def _pace_nvd(has_api_key: bool) -> None:
    """Respect the public API's five requests per rolling 30-second window."""
    if has_api_key:
        return  # The bounded keyed scan makes at most 24 requests.
    while True:
        with _NVD_LOCK:
            now = time.monotonic()
            while _NVD_REQUESTS and now - _NVD_REQUESTS[0] >= 30.5:
                _NVD_REQUESTS.popleft()
            if len(_NVD_REQUESTS) < 5:
                _NVD_REQUESTS.append(now)
                return
            delay = _NVD_REQUESTS[0] + 30.5 - now
        time.sleep(max(0.05, delay))


def _fetch_nvd(source: dict[str, Any], since: datetime | None,
               limit: int, terms: list[str]) -> list[dict[str, Any]]:
    base = source.get("url") or NVD_URL
    parsed_base = urlparse(base)
    if (parsed_base.hostname != "services.nvd.nist.gov"
            or parsed_base.path.rstrip("/") != "/rest/json/cves/2.0"):
        raise ConnectorError("NVD source.url must point to services.nvd.nist.gov CVE API 2.0")
    start = since or (datetime.now(timezone.utc) - timedelta(days=7))
    end = datetime.now(timezone.utc)
    if start > end:
        return []
    if end - start > timedelta(days=120):
        raise ConnectorError("NVD permits at most 120 days per query; backfill in smaller windows")
    requested_terms = [term for term in (terms if source.get("keywords") else NVD_DEFAULT_QUERIES)
                       if len(term) >= 3]
    if not requested_terms:
        raise ConnectorError("NVD requires a specific AI product/technology keyword (at least 3 characters)")
    if len(requested_terms) > MAX_NVD_QUERIES:
        raise ConnectorError(
            f"NVD has {len(requested_terms)} keywords, above the bounded {MAX_NVD_QUERIES}; "
            "split them into multiple source configurations"
        )
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else None
    for term in requested_terms:
        offset = 0
        for page in range(MAX_NVD_PAGES_PER_TERM):
            params = {
                "keywordSearch": term,
                "lastModStartDate": start.isoformat(timespec="seconds"),
                "lastModEndDate": end.isoformat(timespec="seconds"),
                "resultsPerPage": min(100, max(1, limit)),
                "startIndex": offset,
            }
            _pace_nvd(bool(headers))
            payload, _ = _get_json(_query_url(base, **params), headers=headers)
            if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                raise ConnectorError("NVD response lacks the vulnerabilities array")
            page_items = payload["vulnerabilities"]
            for wrapper in page_items:
                cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
                if not isinstance(cve, dict) or not cve.get("id") or cve["id"] in seen:
                    continue
                cve_id = str(cve["id"])
                if not re.fullmatch(r"CVE-\d{4}-\d{4,19}", cve_id, re.I):
                    continue
                descriptions = cve.get("descriptions") or []
                description = next((item.get("value", "") for item in descriptions
                                    if item.get("lang") == "en"), "")
                if not description and descriptions:
                    description = descriptions[0].get("value", "")
                affected = _nvd_affected(cve)
                matching_text = " ".join((description, " ".join(product for product, _ in affected),
                                          cve_id))
                if not _matches(matching_text, terms):
                    continue
                refs = _unique([_safe_reference(item.get("url")) for item in cve.get("references", [])
                                if isinstance(item, dict)])
                score, severity = _nvd_metric(cve)
                for product, versions in affected:
                    results.append(_record(
                        source, external_id=cve_id + ("::" + product if product else ""),
                        title=cve_id + ": " + description[:120],
                        summary=description[:500], body=description,
                        url="https://nvd.nist.gov/vuln/detail/" + cve_id,
                        published_at=_iso(cve.get("published")),
                        updated_at=_iso(cve.get("lastModified")), kind="vulnerability",
                        identifiers=[cve_id], product=product, cvss=score,
                        severity=severity, versions=versions, refs=refs, raw=cve,
                    ))
                    if len(results) > limit:
                        raise ConnectorError(
                            f"NVD has more than {limit} matching product records; "
                            "increase the pipeline limit or narrow source keywords"
                        )
                seen.add(cve_id)
            offset += len(page_items)
            total = payload.get("totalResults", offset)
            if not isinstance(total, int):
                raise ConnectorError("NVD totalResults must be an integer")
            if offset >= total:
                break
            if not page_items:
                raise ConnectorError("NVD returned an empty page before totalResults was reached")
        else:
            raise ConnectorError(
                f"NVD keyword {term!r} exceeds {MAX_NVD_PAGES_PER_TERM} bounded pages; "
                "narrow the time window or split the source"
            )
    return results


def _next_link(headers: dict[str, str]) -> str | None:
    value = next((item for key, item in headers.items() if key.lower() == "link"), "")
    for part in value.split(","):
        match = re.search(r'<([^>]+)>;\s*rel="?next"?', part)
        if match:
            return match.group(1)
    return None


def _github_metric(item: dict[str, Any]) -> float | None:
    severities = item.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        metric = severities.get(key) or {}
        if metric.get("score") is not None:
            return float(metric["score"])
    metric = item.get("cvss") or {}
    return float(metric["score"]) if metric.get("score") is not None else None


def _fetch_github(source: dict[str, Any], since: datetime | None,
                  limit: int, terms: list[str]) -> list[dict[str, Any]]:
    base = source.get("url") or GITHUB_URL
    parsed = urlparse(base)
    if parsed.hostname == "github.com" and parsed.path.rstrip("/") == "/advisories":
        base = GITHUB_URL
    elif parsed.hostname != "api.github.com" or parsed.path.rstrip("/") != "/advisories":
        raise ConnectorError("GitHub source.url must be the public /advisories REST endpoint")
    # A broad unauthenticated global scan can exhaust the five-page safety
    # budget before reaching AI advisories. Initial live polling starts with
    # two days; historical backfill should use explicitly bounded windows.
    start = since or (datetime.now(timezone.utc) - timedelta(days=2))
    params = {
        "type": "reviewed", "sort": "updated", "direction": "desc",
        "per_page": min(100, max(1, limit)),
        "modified": ">=" + start.isoformat(timespec="seconds"),
    }
    url = _query_url(base, **params)
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for page in range(MAX_GITHUB_PAGES):
        payload, response_headers = _get_json(url, headers=headers)
        if not isinstance(payload, list):
            raise ConnectorError("GitHub advisories response must be a list")
        for item in payload:
            if not isinstance(item, dict) or not item.get("ghsa_id"):
                continue
            if item.get("withdrawn_at"):
                continue
            changed = _utc(item.get("updated_at")) or _utc(item.get("published_at"))
            if changed and changed < start:
                continue
            vulnerabilities = item.get("vulnerabilities") or []
            affected: dict[str, dict[str, list[str]]] = {}
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                package = vulnerability.get("package") or {}
                product = str(package.get("name") or "").strip()
                if not product:
                    continue
                group = affected.setdefault(product, {"versions": [], "fixed_versions": [],
                                                       "ecosystems": []})
                if package.get("ecosystem"):
                    group["ecosystems"].append(str(package["ecosystem"]))
                if vulnerability.get("vulnerable_version_range"):
                    group["versions"].append(str(vulnerability["vulnerable_version_range"]))
                if vulnerability.get("first_patched_version"):
                    group["fixed_versions"].append(str(vulnerability["first_patched_version"]))
            products = list(affected)
            text = " ".join((item.get("summary") or "", item.get("description") or "",
                             " ".join(products)))
            if not _matches(text, terms):
                continue
            ghsa = str(item["ghsa_id"])
            if not re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", ghsa, re.I):
                continue
            if ghsa in seen:
                continue
            ids = [entry.get("value", "") for entry in item.get("identifiers", [])
                   if isinstance(entry, dict)]
            ids.extend([ghsa, item.get("cve_id") or ""])
            groups = list(affected.items()) or [("", {"versions": [], "fixed_versions": [],
                                                     "ecosystems": []})]
            for product, ranges in groups:
                # A bare asset name cannot disambiguate, for example, an npm
                # package and a PyPI package with the same name.
                ambiguous_ecosystem = len(set(ranges["ecosystems"])) > 1
                results.append(_record(
                    source, external_id=ghsa + ("::" + product if product else ""),
                    title=item.get("summary") or ghsa,
                    summary=item.get("summary"), body=item.get("description"),
                    url=_safe_reference(item.get("html_url")) or
                        "https://github.com/advisories/" + ghsa,
                    published_at=_iso(item.get("published_at")),
                    updated_at=_iso(item.get("updated_at")), kind="vulnerability",
                    identifiers=_unique(ids), product=product,
                    cvss=_github_metric(item), severity=str(item.get("severity") or "").upper(),
                    versions=[] if ambiguous_ecosystem else _unique(ranges["versions"]),
                    fixed_versions=[] if ambiguous_ecosystem else _unique(ranges["fixed_versions"]),
                    refs=_unique([_safe_reference(ref) for ref in item.get("references", [])]),
                    raw=item,
                ))
                if len(results) > limit:
                    raise ConnectorError(
                        f"GitHub advisories has more than {limit} matching product records; "
                        "increase the pipeline limit or narrow source keywords"
                    )
            seen.add(ghsa)
        next_url = _next_link(response_headers)
        if not next_url:
            return results
        next_parsed = urlparse(next_url)
        if (next_parsed.hostname != "api.github.com"
                or next_parsed.path.rstrip("/") != "/advisories"):
            raise ConnectorError("GitHub pagination left the public advisories endpoint")
        next_query = dict(parse_qsl(next_parsed.query))
        if any(next_query.get(key) != params[key] for key in ("type", "sort", "direction", "modified")):
            raise ConnectorError("GitHub pagination changed the bounded query filters")
        url = _validated_url(next_url)
    raise ConnectorError(
        f"GitHub advisories exceeds the bounded {MAX_GITHUB_PAGES}-page scan; "
        "narrow the time window or split the source"
    )


def _fetch_kev(source: dict[str, Any], since: datetime | None,
               limit: int, terms: list[str]) -> list[dict[str, Any]]:
    base = source.get("url") or CISA_URL
    parsed_base = urlparse(base)
    if (parsed_base.hostname not in {"www.cisa.gov", "cisa.gov"}
            or not parsed_base.path.endswith("/known_exploited_vulnerabilities.json")):
        raise ConnectorError("CISA KEV source.url must point to the official cisa.gov JSON feed")
    payload, _ = _get_json(base)
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ConnectorError("CISA KEV JSON lacks the vulnerabilities array")
    results: list[dict[str, Any]] = []
    for item in payload["vulnerabilities"]:
        if not isinstance(item, dict) or not item.get("cveID"):
            continue
        text = " ".join(str(item.get(key) or "") for key in
                        ("vendorProject", "product", "vulnerabilityName", "shortDescription"))
        if not _matches(text, terms):
            continue
        cve_id = str(item["cveID"])
        action = str(item.get("requiredAction") or "")
        notes = str(item.get("notes") or "")
        body = "\n".join(part for part in
                         (str(item.get("shortDescription") or ""),
                          "Required action: " + action if action else "", notes) if part)
        results.append(_record(
            source, external_id=cve_id, title=item.get("vulnerabilityName") or cve_id,
            summary=item.get("shortDescription"), body=body,
            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            published_at=_iso(item.get("dateAdded")),
            updated_at=None, kind="vulnerability",
            identifiers=[cve_id],
            product=str(item.get("product") or item.get("vendorProject") or ""),
            refs=["https://nvd.nist.gov/vuln/detail/" + cve_id],
            # A catalog release timestamp applies to the whole feed, not this
            # entry. Including it here would falsely update every KEV daily.
            raw={**item, "known_exploited": True},
        ))
        if len(results) > limit:
            raise ConnectorError(
                f"CISA KEV has more than {limit} matching entries; "
                "increase the pipeline limit or narrow source keywords"
            )
    return results


CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
           "C": {"N": 0.85, "L": 0.68, "H": 0.5}},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss3_base_score(vector: str) -> tuple[float, str] | None:
    """CVSS 3.0/3.1 base score from a vector string, per the FIRST specification.

    OSV publishes only the vector; deriving the numeric score lets standalone
    GHSA advisories carry the same CVSS enrichment dimension as NVD records.
    """
    if not vector.upper().startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics = {}
    for part in vector.upper().split("/"):
        key, _, value = part.partition(":")
        if key and value:
            metrics[key] = value
    try:
        if metrics["S"] not in {"U", "C"}:
            return None
        scope_changed = metrics["S"] == "C"
        av = CVSS3_WEIGHTS["AV"][metrics["AV"]]
        ac = CVSS3_WEIGHTS["AC"][metrics["AC"]]
        pr = CVSS3_WEIGHTS["PR"]["C" if scope_changed else "U"][metrics["PR"]]
        ui = CVSS3_WEIGHTS["UI"][metrics["UI"]]
        cia = [CVSS3_WEIGHTS["CIA"][metrics[key]] for key in ("C", "I", "A")]
    except KeyError:
        return None
    iss = 1.0 - (1.0 - cia[0]) * (1.0 - cia[1]) * (1.0 - cia[2])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0, "NONE"
    score = min(10.0, (impact + exploitability) * (1.08 if scope_changed else 1.0))
    score = math.ceil(score * 10 - 1e-8) / 10  # FIRST Roundup to one decimal.
    severity = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7
                else "MEDIUM" if score >= 4 else "LOW")
    return score, severity


def _osv_metric(vuln: dict[str, Any]) -> tuple[float | None, str]:
    entries = vuln.get("severity")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                parsed = cvss3_base_score(str(entry.get("score") or ""))
                if parsed:
                    return parsed
    return None, ""


def _osv_version_ranges(affected: dict[str, Any]) -> list[str]:
    """Translate OSV range events into the project's interval expression list."""
    ranges: list[str] = []
    for entry in affected.get("ranges") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("type") or "").upper() not in {"ECOSYSTEM", "SEMVER"}:
            # GIT ranges contain commits, not comparable release versions.
            continue
        introduced: str | None = None
        for event in entry.get("events") or []:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                introduced = str(event["introduced"])
                continue
            upper = ("<" + str(event["fixed"]) if event.get("fixed") else
                     "<=" + str(event["last_affected"]) if event.get("last_affected") else
                     "<" + str(event["limit"]) if event.get("limit") else "")
            if upper:
                if introduced is not None:
                    bounds = (">=" + introduced if introduced not in {"0", ""} else "", upper)
                    ranges.append(", ".join(part for part in bounds if part))
                introduced = None
        if introduced is not None:
            # OSV's introduced=0 means affected from the earliest release.
            # An open range with no fixed event must not disappear entirely.
            ranges.append(">=" + (introduced if introduced else "0"))
    # OSV often enumerates every affected release in addition to a numeric
    # ecosystem interval. Skip only releases that the matcher can prove are
    # covered; retain outliers and unparsable releases as explicit evidence.
    # The full source enumeration also remains in raw_json.
    for version in affected.get("versions") or []:
        if isinstance(version, str) and version.strip():
            normalized = version.strip()
            if match_version(normalized, ranges, []) == "affected":
                continue
            ranges.append("==" + normalized)
    return _unique(ranges)


def _fetch_osv(source: dict[str, Any], since: datetime | None,
               limit: int, terms: list[str]) -> list[dict[str, Any]]:
    """Query OSV.dev per configured AI package; no API key, no authentication.

    ``package`` items use ``ecosystem:name`` syntax, e.g. ``pypi:ollama`` or
    ``go:github.com/ollama/ollama``.
    """
    base = source.get("url") or OSV_URL
    parsed_base = urlparse(base)
    if (parsed_base.hostname != "api.osv.dev"
            or parsed_base.path.rstrip("/") != "/v1/query"):
        raise ConnectorError("OSV source.url must point to api.osv.dev /v1/query")
    raw_packages = source.get("packages")
    if raw_packages is None:
        packages = list(DEFAULT_OSV_PACKAGES)
    elif isinstance(raw_packages, str):
        packages = [part.strip() for part in re.split(r"[,;\n]", raw_packages) if part.strip()]
    elif isinstance(raw_packages, (list, tuple)):
        packages = [str(part).strip() for part in raw_packages if str(part).strip()]
    else:
        raise ValueError("source.packages must be a list of ecosystem:name strings")
    if not packages or len(packages) > 20:
        raise ConnectorError("OSV source needs 1-20 packages; split into more sources")
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for package in packages:
        ecosystem, _, name = package.partition(":")
        if not name or not ecosystem:
            raise ConnectorError(f"OSV package {package!r} must be ecosystem:name")
        osv_ecosystem = OSV_ECOSYSTEMS.get(ecosystem.lower())
        if not osv_ecosystem:
            raise ConnectorError(f"OSV ecosystem {ecosystem!r} is not in the supported map")
        package_request: dict[str, Any] = {"package": {"ecosystem": osv_ecosystem,
                                                       "name": name}}
        page_tokens: set[str] = set()
        for page in range(MAX_OSV_PAGES_PER_PACKAGE):
            payload, _ = _post_json(base, package_request)
            if not isinstance(payload, dict):
                raise ConnectorError("OSV response must be a JSON object")
            # OSV answers "no advisories" with a bare {} instead of {"vulns": []}.
            package_vulns = payload.get("vulns") or []
            if not isinstance(package_vulns, list):
                raise ConnectorError("OSV response vulns must be a list")
            for vuln in package_vulns:
                if not isinstance(vuln, dict) or not vuln.get("id"):
                    continue
                osv_id = str(vuln["id"])
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,100}", osv_id):
                    continue
                aliases = [str(alias) for alias in vuln.get("aliases", []) if alias]
                cves = [alias for alias in aliases if re.fullmatch(r"CVE-\d{4}-\d{4,19}", alias)]
                ghsas = [alias for alias in aliases if re.fullmatch(
                    r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", alias, re.I)]
                canonical = cves[0] if cves else (ghsas[0] if ghsas else osv_id.upper())
                # OSV id and package identify the source record. CVE aliases can
                # appear later, so a CVE-derived external id would duplicate it.
                external = osv_id.upper() + "::" + osv_ecosystem + ":" + name
                if external in seen:
                    continue
                modified = _utc(vuln.get("modified")) or _utc(vuln.get("published"))
                if since and modified and modified < since:
                    continue
                updated_at_iso = _iso(vuln.get("modified"))
                summary = str(vuln.get("summary") or "")
                details = str(vuln.get("details") or "")
                if not _matches(" ".join((summary, details, name)), terms):
                    continue
                score, severity = _osv_metric(vuln)
                fixed: list[str] = []
                versions: list[str] = []
                matched_package = False
                for affected in vuln.get("affected") or []:
                    if not isinstance(affected, dict):
                        continue
                    package_info = affected.get("package") or {}
                    if (str(package_info.get("name") or "") != name or
                            str(package_info.get("ecosystem") or "") != osv_ecosystem):
                        continue
                    matched_package = True
                    versions.extend(_osv_version_ranges(affected))
                    for entry in affected.get("ranges") or []:
                        for event in (entry.get("events") or []) if isinstance(entry, dict) else []:
                            if isinstance(event, dict) and event.get("fixed"):
                                fixed.append(str(event["fixed"]))
                if not matched_package:
                    continue
                refs = _unique([_safe_reference(str(ref.get("url") or ""))
                                for ref in vuln.get("references", []) if isinstance(ref, dict)])
                seen.add(external)
                results.append(_record(
                    source, external_id=external, title=summary or osv_id,
                    summary=summary, body=details,
                    url=f"https://osv.dev/vulnerability/{osv_id}",
                    published_at=_iso(vuln.get("published")),
                    updated_at=updated_at_iso, kind="vulnerability",
                    identifiers=_unique([canonical] + aliases + [osv_id.upper()]),
                    product=name, cvss=score, severity=severity,
                    versions=_unique(versions), fixed_versions=_unique(fixed),
                    refs=refs, raw={**vuln, "queried_package": package},
                ))
                if len(results) > limit:
                    raise ConnectorError(
                        f"OSV has more than {limit} matching records; "
                        "increase the pipeline limit or split source packages")
            token = payload.get("next_page_token")
            if not token:
                break
            if not isinstance(token, str) or token in page_tokens:
                raise ConnectorError("OSV returned an invalid or repeated pagination token")
            page_tokens.add(token)
            package_request = {"package": {"ecosystem": osv_ecosystem, "name": name},
                               "page_token": token}
        else:
            raise ConnectorError(
                f"OSV package {package!r} exceeds {MAX_OSV_PAGES_PER_PACKAGE} pages; "
                "narrow the source or increase the bounded page budget")
    return results


def fetch_epss(cves: list[str]) -> dict[str, dict[str, Any]]:
    """FIRST EPSS exploitation-probability scores; read-only, no API key.

    Returns ``{cve: {"epss": float, "percentile": float, "date": str}}`` for the
    CVEs EPSS currently scores; missing CVEs are absent from the result.
    """
    cleaned = [cve for cve in dict.fromkeys(cves)
               if re.fullmatch(r"CVE-\d{4}-\d{4,19}", str(cve).strip(), re.I)]
    scores: dict[str, dict[str, Any]] = {}
    for batch_start in range(0, len(cleaned), 50):
        batch = cleaned[batch_start:batch_start + 50]
        # FIRST EPSS takes comma-separated CVEs; repeated ?cve= params are
        # silently ignored by the API.
        query = "cve=" + ",".join(batch)
        payload, _ = _get_json(f"{EPSS_URL}?{query}")
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ConnectorError("EPSS response lacks the data array")
        for item in payload["data"]:
            if not isinstance(item, dict) or not item.get("cve"):
                continue
            try:
                scores[str(item["cve"]).upper()] = {
                    "epss": float(item.get("epss")),
                    "percentile": float(item.get("percentile")),
                    "date": str(item.get("date") or ""),
                }
            except (TypeError, ValueError):
                continue
    return scores


class _PlainText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self.hidden += 1
        elif tag in {"br", "p", "div", "li"}:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1
        elif tag in {"p", "div", "li"}:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)


def _plain(value: str) -> str:
    parser = _PlainText()
    parser.feed(value or "")
    return " ".join("".join(parser.parts).split())


class _HTMLDocument(HTMLParser):
    """Extract readable text from one configured policy/standard page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.title_parts: list[str] = []
        self.main_parts: list[str] = []
        self.article_parts: list[str] = []
        self.body_parts: list[str] = []
        self.description = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = dict(attrs)
        if tag == "meta":
            label = (attributes.get("name") or attributes.get("property") or "").lower()
            if label in {"description", "og:description"} and not self.description:
                self.description = (attributes.get("content") or "").strip()
        if tag not in {"meta", "link", "br", "hr", "img", "input", "source", "area"}:
            self.stack.append(tag)
        if tag in {"p", "div", "li", "br", "h1", "h2", "h3"}:
            self._space()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"p", "div", "li", "h1", "h2", "h3"}:
            self._space()
        if tag in self.stack:
            while self.stack:
                if self.stack.pop() == tag:
                    break

    def handle_data(self, data: str) -> None:
        if any(tag in self.stack for tag in ("script", "style", "noscript", "svg", "nav", "footer")):
            return
        if "title" in self.stack:
            self.title_parts.append(data)
        if "body" in self.stack:
            self.body_parts.append(data)
        if "article" in self.stack:
            self.article_parts.append(data)
        if "main" in self.stack:
            self.main_parts.append(data)

    def _space(self) -> None:
        if "body" in self.stack:
            self.body_parts.append(" ")
        if "article" in self.stack:
            self.article_parts.append(" ")
        if "main" in self.stack:
            self.main_parts.append(" ")

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split())

    @property
    def body(self) -> str:
        parts = self.main_parts or self.article_parts or self.body_parts
        return " ".join("".join(parts).split())


def _header(headers: dict[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


def _fetch_static_html(source: dict[str, Any], since: datetime | None,
                       limit: int, terms: list[str]) -> list[dict[str, Any]]:
    """Read exactly one configured URL; never crawl links embedded in its HTML."""
    url = source.get("url")
    if not url:
        raise ConnectorError("Static HTML source.url is required")
    data, headers = _http_get(url, accept="text/html, application/xhtml+xml",
                              max_bytes=2 * 1024 * 1024)
    content_type = _header(headers, "Content-Type") or ""
    charset_match = re.search(r"charset=([\w-]+)", content_type, re.I)
    if charset_match:
        charset = charset_match.group(1)
    else:
        html_declared = re.search(rb"<meta\b[^>]*charset\s*=\s*['\"]?([\w-]+)",
                                  data[:4096], re.I)
        charset = html_declared.group(1).decode("ascii") if html_declared else "utf-8"
    if charset.lower() in {"gbk", "gb2312"}:
        charset = "gb18030"
    try:
        html = data.decode(charset, errors="replace")
    except LookupError as exc:
        raise ConnectorError(f"Unknown HTML charset {charset!r} from {url}") from exc
    document = _HTMLDocument()
    document.feed(html)
    body = document.body
    title = document.title or urlparse(url).hostname or "Static page"
    summary = _plain(document.description) or body[:500]
    if not _matches(" ".join((title, summary, body)), terms):
        return []
    last_modified = _iso(_header(headers, "Last-Modified"))
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return [_record(
        source, external_id=url, title=title,
        summary=summary, body=body[:120000], url=url,
        published_at=None, updated_at=last_modified,
        kind=_rss_kind(str(source.get("category") or "")),
        identifiers=_identifiers(title, summary, body),
        raw={"content_sha256": digest, "last_modified": _header(headers, "Last-Modified"),
             "content_type": content_type, "configured_url": url},
    )][:limit]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _child_text(element: ElementTree.Element, names: set[str]) -> str:
    for child in element:
        if _local(child.tag) in names:
            return " ".join(part.strip() for part in child.itertext() if part.strip())
    return ""


def _feed_link(entry: ElementTree.Element, base: str) -> str:
    for child in entry:
        if _local(child.tag) != "link":
            continue
        if child.attrib.get("rel", "alternate") != "alternate":
            continue
        candidate = child.attrib.get("href") or (child.text or "").strip()
        if candidate:
            resolved = _safe_reference(candidate, base=base)
            if resolved:
                return resolved
    # Some valid RSS feeds (including Hugging Face's blog) publish the article
    # URL only as a permalink GUID. Keep it as a display-only reference.
    for child in entry:
        if _local(child.tag) not in {"guid", "id"}:
            continue
        candidate = (child.text or "").strip()
        if candidate.startswith("https://"):
            resolved = _safe_reference(candidate)
            if resolved:
                return resolved
    return ""


def _rss_kind(category: str) -> str:
    lowered = category.casefold()
    if any(word in lowered for word in ("paper", "research", "论文", "学术")):
        return "paper"
    if any(word in lowered for word in ("standard", "规范", "标准")):
        return "standard"
    if any(word in lowered for word in ("policy", "regulation", "law", "政策", "法规")):
        return "policy"
    return "article"


def _fetch_rss(source: dict[str, Any], since: datetime | None,
               limit: int, terms: list[str]) -> list[dict[str, Any]]:
    base = source.get("url")
    if not base:
        raise ConnectorError("RSS source.url is required")
    data, _ = _http_get(base, accept="application/rss+xml, application/atom+xml, application/xml",
                        max_bytes=XML_RESPONSE_BYTES)
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ConnectorError("RSS/Atom feed contains a forbidden DTD or entity declaration")
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise ConnectorError(f"Invalid RSS/Atom XML from {base}: {exc}") from exc
    entries = [element for element in root.iter() if _local(element.tag) in {"item", "entry"}]
    category = str(source.get("category") or "")
    kind = _rss_kind(category)
    ordered: list[tuple[datetime, dict[str, Any]]] = []
    for item in entries:
        title = _plain(_child_text(item, {"title"}))
        summary = _plain(_child_text(item, {"summary", "description"}))
        body = _plain(_child_text(item, {"encoded", "content"})) or summary
        if not _matches(" ".join((title, summary, body)), terms):
            continue
        published = _child_text(item, {"published", "pubDate", "date", "issued"})
        updated = _child_text(item, {"updated", "modified"})
        stamp = _utc(updated) or _utc(published) or datetime.min.replace(tzinfo=timezone.utc)
        link = _feed_link(item, base)
        external_id = _child_text(item, {"id", "guid"}) or link or title
        if not external_id:
            continue
        ids = _identifiers(title, summary, body)
        raw = {
            "title": title, "summary": summary, "content": body,
            "published": published, "updated": updated, "link": link,
            "categories": [_plain("".join(child.itertext())) for child in item
                           if _local(child.tag) == "category"],
        }
        record = _record(
            source, external_id=external_id, title=title, summary=summary,
            body=body, url=link or base, published_at=_iso(published),
            updated_at=_iso(updated), kind=kind, identifiers=ids, raw=raw,
        )
        ordered.append((stamp, record))
    ordered.sort(key=lambda pair: pair[0], reverse=True)
    if len(ordered) > limit:
        raise ConnectorError(
            f"RSS/Atom has more than {limit} matching entries; "
            "increase the pipeline limit or narrow source keywords"
        )
    return [record for _, record in ordered]


def fetch_source(source: dict[str, Any], since: str | None = None,
                 limit: int = 100) -> list[dict[str, Any]]:
    """Fetch a bounded increment from one configured public source.

    ``since`` is inclusive UTC. NVD and GitHub use server-side updated filters.
    KEV has no per-record update timestamp, and RSS/HTML may change without a
    reliable per-item Last-Modified header. Those sources are fully reconciled
    within the configured result bound by the caller's idempotent upsert.
    """
    if not isinstance(source, dict):
        raise TypeError("source must be a dictionary")
    if not source.get("id") or not source.get("type"):
        raise ValueError("source requires non-empty id and type")
    if not source.get("enabled", True):
        return []
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")
    bounded_limit = min(limit, MAX_RESULTS)
    parsed_since = _since(since)
    terms = _keywords(source)
    if not terms:
        raise ValueError("source.keywords must contain at least one AI-related term")
    kind = source["type"]
    try:
        if kind == "nvd":
            return _fetch_nvd(source, parsed_since, bounded_limit, terms)
        if kind == "github_advisories":
            return _fetch_github(source, parsed_since, bounded_limit, terms)
        if kind == "cisa_kev":
            return _fetch_kev(source, parsed_since, bounded_limit, terms)
        if kind == "osv":
            return _fetch_osv(source, parsed_since, bounded_limit, terms)
        if kind == "rss":
            return _fetch_rss(source, parsed_since, bounded_limit, terms)
        if kind == "static_html":
            return _fetch_static_html(source, parsed_since, bounded_limit, terms)
    except ConnectorError as exc:
        raise ConnectorError(f"Source {source['id']} ({kind}): {exc}") from exc
    raise ValueError(f"Unsupported source.type: {kind!r}")
