from datetime import datetime, timedelta, timezone
import requests
from app.core.config import settings

HEADERS = {"User-Agent": "CyberThreatRAG/1.0 defensive research"}

def _json(url, params=None, headers=None):
    response = requests.get(url, params=params, headers={**HEADERS, **(headers or {})}, timeout=90)
    response.raise_for_status()
    return response.json()

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


