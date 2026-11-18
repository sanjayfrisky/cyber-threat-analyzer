from datetime import datetime, timedelta, timezone
import logging
import requests
from app.core.config import settings

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "CyberThreatRAG/1.0 defensive research"}
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _json(url, params=None, headers=None):
    response = requests.get(url, params=params, headers={**HEADERS, **(headers or {})}, timeout=90)
    response.raise_for_status()
    return response.json()


def _nvd_cve_to_record(cve_item: dict) -> dict | None:
    """Convert a single NVD CVE API item into an ingestion record dict."""
    try:
        cve = cve_item.get("cve", {})
        cve_id = cve.get("id", "unknown")
        descriptions = cve.get("descriptions", [])
        en_desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                data = metric_list[0].get("cvssData", {})
                cvss_score = data.get("baseScore")
                severity = data.get("baseSeverity", metric_list[0].get("baseSeverity", "UNKNOWN"))
                break

        refs = [r.get("url", "") for r in cve.get("references", [])[:5]]
        affected = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    affected.append(cpe.get("criteria", ""))
        affected_str = ", ".join(affected[:10]) if affected else "See NVD for affected products."

        text = (
            f"CVE ID: {cve_id}. "
            f"Description: {en_desc}. "
            f"CVSS Score: {cvss_score}. Severity: {severity}. "
            f"Affected products: {affected_str}. "
            f"References: {', '.join(refs)}."
        )
        return {
            "source": "NVD",
            "external_id": cve_id,
            "title": f"{cve_id} - {en_desc[:120]}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "category": "cve",
            "text": text,
            "metadata": {
                "cvss_score": cvss_score,
                "severity": severity,
                "references": refs,
            },
        }
    except Exception as exc:
        logger.warning("Failed to parse NVD CVE item: %s", exc)
        return None


def load_nvd_recent(days: int = 120) -> list[dict]:
    """Fetch CVEs published in the last `days` days from NVD."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    }
    logger.info("Fetching NVD CVEs from %s to %s", params["pubStartDate"], params["pubEndDate"])
    data = _json(NVD_BASE, params=params)
    vulnerabilities = data.get("vulnerabilities", [])
    logger.info("NVD returned %d CVEs", len(vulnerabilities))
    records = []
    for item in vulnerabilities:
        rec = _nvd_cve_to_record(item)
        if rec:
            records.append(rec)
    return records


def load_nvd_cve_by_id(cve_id: str) -> dict | None:
    """Fetch a single CVE by ID from NVD (supports historical CVEs like CVE-2021-44228)."""
    logger.info("Fetching NVD CVE by ID: %s", cve_id)
    data = _json(NVD_BASE, params={"cveId": cve_id})
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        logger.warning("NVD returned no data for CVE ID: %s", cve_id)
        return None
    return _nvd_cve_to_record(vulnerabilities[0])

def load_cisa_kev():
    payload = _json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    result = []
    for row in payload.get("vulnerabilities", []):
        cve = row.get("cveID", "unknown")
        text = (f"CVE: {cve}. Vendor: {row.get('vendorProject','')}. Product: {row.get('product','')}. "
                f"Name: {row.get('vulnerabilityName','')}. Description: {row.get('shortDescription','')}. "
                f"Date added: {row.get('dateAdded','')}. Required action: {row.get('requiredAction','')}.")
        result.append({"source":"CISA_KEV","external_id":f"CISA-KEV-{cve}",
            "title":f"{cve} - {row.get('vulnerabilityName','Known exploited vulnerability')}",
            "url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "category":"known_exploited_vulnerability","text":text,"metadata":row})
    return result

def load_mitre_attack():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    bundle = _json(url)
    result = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})
        tid = ref.get("external_id")
        if not tid:
            continue
        text = (f"Technique ID: {tid}. Name: {obj.get('name','')}. Description: {obj.get('description','')}. "
                f"Detection: {obj.get('x_mitre_detection','')}. Platforms: {', '.join(obj.get('x_mitre_platforms', []))}.")
        result.append({"source":"MITRE_ATTACK","external_id":f"MITRE-{tid}",
            "title":f"{tid} - {obj.get('name','ATT&CK technique')}",
            "url":f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "category":"attack_technique","text":text,
            "metadata":{"technique_id":tid,"platforms":obj.get("x_mitre_platforms",[])}})
    return result


