import json
import re
import sys
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path when running file directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from google import genai
from google.genai import types
from sqlalchemy.orm import Session
from app.core.config import settings
from app.ai.prompts.screening_prompt import SCREENING_SYSTEM_PROMPT
from app.ai.rag.pipeline import RAGPipeline, build_context

# High-risk heuristic indicators
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"disregard\s+(?:all\s+)?prior\s+prompts",
    r"you\s+are\s+now\s+(?:an?\s+)?unrestricted",
    r"system\s*:\s*override",
    r"jailbreak",
    r"act\s+as\s+DAN\b",
    r"bypass\s+(?:content|security)\s+filters"
]

SUSPICIOUS_COMMAND_PATTERNS = [
    (r"\b(?:powershell(?:\.exe)?|pwsh)\s+-[eE](?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell Execution", "T1059.001"),
    (r"\b(?:cmd(?:\.exe)?\s+/c|bash\s+-c|sh\s+-c)\b", "Command-Line Shell Invocation", "T1059"),
    (r"\b(?:curl|wget)\b[^\n|]+?\|\s*(?:bash|sh)\b", "Remote Script Download and Execution", "T1059.004"),
    (r"\b(?:mimikatz|sekurlsa|kerbrute|responder)\b", "Credential Access Tooling", "T1003"),
    (r"\b(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog)\b", "Ransomware Inhibit System Recovery", "T1490"),
    (r"\b(?:net\s+user\s+/add|net\s+localgroup\s+administrators\s+/add)\b", "Local Account Creation", "T1136.001"),
    (r"\b(?:certutil(?:\.exe)?\s+-urlcache|-decode)\b", "Certutil Download or Decode Evasion", "T1140"),
    (r"\b(?:SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?--|\bUNION\s+SELECT\b)", "SQL Injection Attempt", "T1190"),
    (r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", "Cross-Site Scripting (XSS) Vector", "T1190")
]

def extract_screening_iocs(text: str) -> dict:
    urls = sorted(set(x.rstrip(".,;") for x in re.findall(r"https?://[^\s\]\[()<>\"']+", text, re.I)))
    ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    ips = sorted(ip for ip in ips if all(0 <= int(p) <= 255 for p in ip.split(".")))
    domains = sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)))
    return {
        "ipv4": ips,
        "urls": urls,
        "domains": domains,
        "md5": sorted(set(re.findall(r"\b[a-fA-F0-9]{32}\b", text))),
        "sha1": sorted(set(re.findall(r"\b[a-fA-F0-9]{40}\b", text))),
        "sha256": sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text)))
    }

def detect_heuristic_signals(text: str) -> dict:
    findings = []
    mitre_techniques = set()
    prompt_injection_flag = False

    # Check prompt injection patterns
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            prompt_injection_flag = True
            findings.append("Potential prompt-injection/jailbreak pattern detected in untrusted content.")
            break

    # Check suspicious command patterns
    for pattern, description, technique in SUSPICIOUS_COMMAND_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(f"Heuristic detection: {description}")
            mitre_techniques.add(technique)

    return {
        "prompt_injection_detected": prompt_injection_flag,
        "findings": findings,
        "mitre_techniques": sorted(mitre_techniques)
    }

class ScreeningService:
    def __init__(self):
        self.client = genai.Client(api_key=settings.gemini_api_key)
        self.rag = RAGPipeline()

    def _generate_structured_triage(self, prompt: str) -> dict[str, Any] | None:
        try:
            response = self.client.models.generate_content(
                model=settings.gemini_chat_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SCREENING_SYSTEM_PROMPT,
                    temperature=0.1,
                    response_mime_type="application/json"
                )
            )
            raw = (response.text or "").strip()
            # In case LLM returns markdown formatting like ```json ... ```
            if raw.startswith("```"):
                raw = re.sub(r"^```(?:json)?\s*", "", raw)
                raw = re.sub(r"\s*```$", "", raw)
            return json.loads(raw)
        except Exception:
            return None

    def screen_text(self, db: Session | None, content: str, context: str = "") -> dict:
        sample_text = content[:30000]
        iocs = extract_screening_iocs(sample_text)
        heuristics = detect_heuristic_signals(sample_text)

        # Retrieve relevant threat intelligence if database session is supplied
        retrieved_intel = []
        if db is not None:
            try:
                retrieval_query = f"{context}\n{sample_text[:2000]}"
                retrieved_intel = self.rag.retrieve(db, retrieval_query, top_k=settings.top_k)
            except Exception:
                retrieved_intel = []

        context_str = build_context(retrieved_intel) if retrieved_intel else "No matching threat intelligence records indexed."

        prompt = (
            f"OPERATIONAL CONTEXT: {context or 'None provided'}\n\n"
            f"HEURISTIC SIGNALS DETECTED:\n{json.dumps(heuristics, indent=2)}\n\n"
            f"EXTRACTED INDICATORS (IOCs):\n{json.dumps(iocs, indent=2)}\n\n"
            f"UNTRUSTED CONTENT TO SCREEN:\n{sample_text}\n\n"
            f"RELEVANT THREAT INTELLIGENCE (GROUND TRUTH):\n{context_str}"
        )

        ai_result = self._generate_structured_triage(prompt)

        # Fallback heuristic calculation if AI generation is unavailable
        if not ai_result:
            has_injection = heuristics["prompt_injection_detected"]
            has_suspicious_cmds = bool(heuristics["mitre_techniques"])
            has_iocs = bool(iocs["ipv4"] or iocs["urls"] or iocs["sha256"])

            if has_injection or (has_suspicious_cmds and has_iocs):
                verdict = "MALICIOUS"
                risk_score = 85
                action = "BLOCK"
            elif has_suspicious_cmds or has_iocs:
                verdict = "SUSPICIOUS"
                risk_score = 55
                action = "QUARANTINE"
            else:
                verdict = "BENIGN"
                risk_score = 10
                action = "PASS"

            ai_result = {
                "verdict": verdict,
                "risk_score": risk_score,
                "confidence": 0.70,
                "threat_category": "Heuristic Assessment",
                "prompt_injection_detected": has_injection,
                "mitre_techniques": heuristics["mitre_techniques"],
                "summary": "Automated rule-based screening completed (fallback mode).",
                "findings": heuristics["findings"] or ["No high-risk malicious tokens detected."],
                "recommended_action": action
            }

        # Merge extracted IOCs and citations into response
        sources = [
            {
                "citation": f"S{i}",
                "source": r["source"],
                "id": r["external_id"],
                "title": r["title"],
                "url": r.get("url")
            }
            for i, r in enumerate(retrieved_intel, 1)
        ]

        return {
            "verdict": ai_result.get("verdict", "INCONCLUSIVE"),
            "risk_score": ai_result.get("risk_score", 0),
            "confidence": ai_result.get("confidence", 0.5),
            "threat_category": ai_result.get("threat_category", "Unknown"),
            "prompt_injection_detected": ai_result.get("prompt_injection_detected", heuristics["prompt_injection_detected"]),
            "mitre_techniques": sorted(list(set(ai_result.get("mitre_techniques", []) + heuristics["mitre_techniques"]))),
            "summary": ai_result.get("summary", ""),
            "findings": ai_result.get("findings", heuristics["findings"]),
            "recommended_action": ai_result.get("recommended_action", "QUARANTINE"),
            "iocs": iocs,
            "sources": sources
        }

    def screen_iocs(self, db: Session | None, iocs_input: dict) -> dict:
        formatted_content = (
            f"Screening list of indicators of compromise (IOCs):\n"
            f"IPv4: {iocs_input.get('ipv4', [])}\n"
            f"Domains: {iocs_input.get('domains', [])}\n"
            f"URLs: {iocs_input.get('urls', [])}\n"
            f"Hashes: {iocs_input.get('sha256', []) + iocs_input.get('md5', [])}"
        )
        return self.screen_text(db, formatted_content, context="Batch IOC Screening Request")

