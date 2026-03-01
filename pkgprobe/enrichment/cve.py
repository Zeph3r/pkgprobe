"""
CVE enrichment for InstallPlan: NVD API v2, keyword-first strategy, 24h cache.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, List, Literal, Optional, Tuple

from pkgprobe.models import CveResult, InstallPlan

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 20
CVE_MAX_RESULTS = 20
CACHE_TTL_SECONDS = 24 * 3600
CACHE_DIR_NAME = "cve"

# Match confidence (deterministic)
CONF_CPE_EXACT = 0.9
CONF_CPE_NO_VERSION = 0.75
CONF_KEYWORD_PRODUCT_VERSION = 0.65
CONF_KEYWORD_PRODUCT_ONLY = 0.5
CONF_INSTALLER_TYPE_ONLY = 0.25

HIGH_CONFIDENCE_THRESHOLD = 0.6


def _cache_dir() -> Path:
    home = Path.home()
    return home / ".pkgprobe" / "cache" / CACHE_DIR_NAME


def _cache_key(normalized_query: str, match_type: str) -> str:
    raw = f"{normalized_query.strip()}|{match_type}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _normalize_query(s: str) -> str:
    return " ".join(s.split()) if s else ""


def apply_cache(normalized_query: str, match_type: str) -> Optional[List[dict]]:
    """
    Return cached results if cache exists and is younger than 24h.
    Otherwise return None. Result is list of dicts (serialized CveResult-like).
    """
    cache_dir = _cache_dir()
    key = _cache_key(normalized_query, match_type)
    path = cache_dir / f"{key}.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        ts = data.get("timestamp") or 0
        if (time.time() - ts) >= CACHE_TTL_SECONDS:
            return None
        return data.get("results") or []
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def _write_cache(normalized_query: str, match_type: str, results: List[dict]) -> None:
    cache_dir = _cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    key = _cache_key(normalized_query, match_type)
    path = cache_dir / f"{key}.json"
    payload = {"timestamp": time.time(), "results": results}
    try:
        path.write_text(json.dumps(payload, indent=0), encoding="utf-8")
    except OSError:
        pass


def _get_headers() -> dict:
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        return {"apiKey": api_key}
    return {}


def query_nvd_keyword(keyword: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    """
    Query NVD by keywordSearch. Returns (vulnerabilities list, error_message).
    On success error_message is None. vulnerabilities are raw dicts from NVD.
    """
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{NVD_BASE}?keywordSearch={urllib.parse.quote(keyword, safe='')}&resultsPerPage={CVE_MAX_RESULTS}",
            headers=_get_headers(),
        )
        with urllib.request.urlopen(req, timeout=NVD_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return None, f"{type(e).__name__}: {e!s}"
    vulns = data.get("vulnerabilities") or []
    return vulns, None


def query_nvd_cpe(cpe_name: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    """
    Query NVD by cpeName. Returns (vulnerabilities list, error_message).
    """
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{NVD_BASE}?cpeName={urllib.parse.quote(cpe_name, safe='')}&resultsPerPage={CVE_MAX_RESULTS}",
            headers=_get_headers(),
        )
        with urllib.request.urlopen(req, timeout=NVD_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return None, f"{type(e).__name__}: {e!s}"
    vulns = data.get("vulnerabilities") or []
    return vulns, None


def _cpe_escape(s: str) -> str:
    """Escape for CPE 2.3 component: replace * ? and unprintable."""
    s = (s or "").strip()
    s = re.sub(r"[*?\s]", "_", s)
    return s[:64] if s else "unknown"


def _build_cpe(manufacturer: str, product: str, version: Optional[str]) -> str:
    # part a = application
    v = _cpe_escape(version) if version else "*"
    return f"cpe:2.3:a:{_cpe_escape(manufacturer)}:{_cpe_escape(product)}:{v}:*:*:*:*:*:*:*"


def _extract_cve(item: dict) -> Optional[dict]:
    cve_obj = (item or {}).get("cve")
    if not cve_obj:
        return None
    cve_id = cve_obj.get("id") or ""
    if not cve_id.startswith("CVE-"):
        return None
    descriptions = cve_obj.get("descriptions") or []
    summary = ""
    for d in descriptions:
        if (d.get("lang") or "").lower() == "en":
            summary = (d.get("value") or "").strip()
            break
    if not summary and descriptions:
        summary = (descriptions[0].get("value") or "").strip()
    published = cve_obj.get("published") or ""
    metrics = cve_obj.get("metrics") or {}
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr and isinstance(arr, list) and len(arr) > 0:
            cvss_data = (arr[0].get("cvssData") or arr[0]) if isinstance(arr[0], dict) else {}
            cvss_score = cvss_data.get("baseScore")
            if cvss_score is not None:
                cvss_score = float(cvss_score)
            cvss_severity = (arr[0].get("cvssData") or arr[0]).get("baseSeverity") if isinstance(arr[0], dict) else None
            cvss_severity = cvss_severity or (arr[0].get("baseSeverity") if isinstance(arr[0], dict) else None)
            break
    return {
        "cve_id": cve_id,
        "summary": summary[:2000],
        "published": published,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def normalize_results(
    raw_vulns: List[dict],
    match_type: Literal["cpe", "keyword"],
    match_confidence: float,
) -> List[CveResult]:
    """Convert NVD vulnerability list to CveResult list with match_type and match_confidence."""
    out: List[CveResult] = []
    for item in raw_vulns[:CVE_MAX_RESULTS]:
        c = _extract_cve(item)
        if not c:
            continue
        out.append(
            CveResult(
                cve_id=c["cve_id"],
                summary=c["summary"],
                cvss_score=c.get("cvss_score"),
                cvss_severity=c.get("cvss_severity"),
                published=c.get("published"),
                url=c.get("url", ""),
                match_type=match_type,
                match_confidence=match_confidence,
            )
        )
    return out


def _sort_and_cap(results: List[CveResult]) -> List[CveResult]:
    # Highest CVSS first, then most recently published
    try:
        sorted_list = sorted(
            results,
            key=lambda r: (-(r.cvss_score if r.cvss_score is not None else -1.0), r.published or ""),
            reverse=True,
        )
    except Exception:
        sorted_list = results
    return sorted_list[:CVE_MAX_RESULTS]


def build_query_from_install_plan(plan: InstallPlan) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[float], Optional[str]]:
    """
    Determine what to run: skip, keyword, or CPE.
    Returns: (should_skip, skip_message, keyword_query, cpe_string, keyword_confidence, version_note).
    keyword_confidence is the match_confidence for keyword results (0.5 or 0.65).
    version_note is set when ProductVersion is missing: "Version not detected; results may not apply to this build."
    """
    meta = plan.metadata or {}
    product_name = (meta.get("ProductName") or "").strip() if isinstance(meta.get("ProductName"), str) else ""
    product_version = (meta.get("ProductVersion") or "").strip() if isinstance(meta.get("ProductVersion"), str) else ""
    manufacturer = (meta.get("Manufacturer") or "").strip() if isinstance(meta.get("Manufacturer"), str) else ""

    version_note = None
    if not product_version and product_name:
        version_note = "Version not detected; results may not apply to this build."

    if plan.file_type == "exe":
        if not product_name:
            return True, "CVE check skipped: insufficient product identity.", None, None, None, version_note
        keyword = product_name
        if product_version:
            keyword = f"{product_name} {product_version}"
            conf = CONF_KEYWORD_PRODUCT_VERSION
        else:
            conf = CONF_KEYWORD_PRODUCT_ONLY
        return False, None, _normalize_query(keyword), None, conf, version_note

    if plan.file_type == "msi":
        if not product_name:
            return True, "CVE check skipped: insufficient product identity.", None, None, None, version_note
        keyword = product_name
        if product_version:
            keyword = f"{product_name} {product_version}"
            keyword_conf = CONF_KEYWORD_PRODUCT_VERSION
        else:
            keyword_conf = CONF_KEYWORD_PRODUCT_ONLY
        return False, None, _normalize_query(keyword), None, keyword_conf, version_note

    return True, "CVE check skipped: insufficient product identity.", None, None, None, version_note


def attach_results_to_plan(
    plan: InstallPlan,
    results: List[CveResult],
    cve_check_message: Optional[str],
    version_note: Optional[str],
) -> InstallPlan:
    """Set plan.cve_results, plan.cve_check_message, and optionally append version_note to notes."""
    plan.cve_results = _sort_and_cap(results)
    plan.cve_check_message = cve_check_message
    if version_note:
        plan.notes = list(plan.notes) + [version_note]
    return plan


def enrich_with_cves(plan: InstallPlan, on_warning: Optional[Callable[[str], None]] = None) -> InstallPlan:
    """
    Run CVE enrichment: keyword-first for MSI, keyword-only for EXE; 24h cache; cap 20.
    On NVD failure sets plan.cve_results=[], plan.cve_check_message, does not raise.
    on_warning(msg) is called for "CVE check unavailable: ..." (e.g. console.print).
    """
    should_skip, skip_message, keyword_query, cpe_string, keyword_conf, version_note = build_query_from_install_plan(plan)
    if should_skip and skip_message:
        return attach_results_to_plan(plan, [], skip_message, version_note)

    results: List[CveResult] = []
    keyword_high_conf = False

    if keyword_query:
        cached = apply_cache(keyword_query, "keyword")
        if cached is not None:
            results = [CveResult(**r) if isinstance(r, dict) else r for r in cached]
            keyword_high_conf = any((getattr(r, "match_confidence") or 0) >= HIGH_CONFIDENCE_THRESHOLD for r in results)
        else:
            vulns, err = query_nvd_keyword(keyword_query)
            if err:
                msg = f"CVE check unavailable: {err}"
                if on_warning:
                    on_warning(msg)
                return attach_results_to_plan(plan, [], msg, version_note)
            results = normalize_results(vulns, "keyword", keyword_conf or CONF_KEYWORD_PRODUCT_ONLY)
            keyword_high_conf = (keyword_conf or 0) >= HIGH_CONFIDENCE_THRESHOLD
            _write_cache(keyword_query, "keyword", [r.model_dump(mode="json") for r in results])

    meta = plan.metadata or {}
    product_name = (meta.get("ProductName") or "").strip() if isinstance(meta.get("ProductName"), str) else ""
    product_version = (meta.get("ProductVersion") or "").strip() if isinstance(meta.get("ProductVersion"), str) else ""
    manufacturer = (meta.get("Manufacturer") or "").strip() if isinstance(meta.get("Manufacturer"), str) else ""

    if plan.file_type == "msi" and manufacturer and product_name and product_version:
        if not keyword_high_conf or not results:
            cpe_str = _build_cpe(manufacturer, product_name, product_version)
            cached_cpe = apply_cache(cpe_str, "cpe")
            if cached_cpe is not None:
                cpe_results = [CveResult(**r) if isinstance(r, dict) else r for r in cached_cpe]
                if not results or (cpe_results and (getattr(cpe_results[0], "match_confidence") or 0) >= (getattr(results[0], "match_confidence") if results else 0)):
                    results = cpe_results
            else:
                vulns, err = query_nvd_cpe(cpe_str)
                if err is None and vulns:
                    cpe_results = normalize_results(vulns, "cpe", CONF_CPE_EXACT)
                    _write_cache(cpe_str, "cpe", [r.model_dump(mode="json") for r in cpe_results])
                    if not results or (cpe_results and (cpe_results[0].match_confidence or 0) >= (results[0].match_confidence if results else 0)):
                        results = cpe_results

    return attach_results_to_plan(plan, results, None, version_note)
