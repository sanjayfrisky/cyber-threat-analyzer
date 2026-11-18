"""Tool 7: Security Command Analysis — detects suspicious patterns in shell commands."""
from __future__ import annotations

import logging
import time

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from app.ai.screening import SUSPICIOUS_COMMAND_PATTERNS, detect_heuristic_signals

logger = logging.getLogger(__name__)

def _risk_from_match_count(count: int, prompt_injection: bool = False) -> str:
    if count >= 2:
        return "CRITICAL"
    if count == 1 or prompt_injection:
        return "HIGH"
    return "BENIGN"


class CommandAnalysisInput(BaseModel):
    command: str = Field(
        description=(
            "A PowerShell, CMD, Bash, or shell command string to analyse for "
            "suspicious or malicious patterns. The command is NEVER executed."
        )
    )


@tool(args_schema=CommandAnalysisInput)
def analyze_command(command: str) -> dict:
    """
    Identify suspicious patterns in shell commands and map them to MITRE ATT&CK techniques.

    Analyses PowerShell, CMD, Bash, or generic shell commands for:
    - Encoded/obfuscated execution
    - Remote download and execution chains
    - Credential dumping tools (mimikatz, sekurlsa)
    - Ransomware recovery inhibition
    - SQL injection patterns
    - Cross-site scripting (XSS) vectors

    THIS TOOL NEVER EXECUTES THE COMMAND. Analysis is regex-based only.

    Returns matched patterns, associated MITRE ATT&CK technique IDs, and risk level.
    """
    t0 = time.perf_counter()
    logger.info("[tool] analyze_command | command_len=%d", len(command))

    if not command or not command.strip():
        return {
            "command": command,
            "matches": [],
            "mitre_techniques": [],
            "risk_level": "BENIGN",
            "note": "Empty command provided",
        }

    # Reuse existing heuristic detection from app/ai/screening.py
    heuristic_result = detect_heuristic_signals(command)

    matches = heuristic_result.get("findings", [])
    mitre_techniques = heuristic_result.get("mitre_techniques", [])
    prompt_injection = heuristic_result.get("prompt_injection_detected", False)

    # Build detailed match list from SUSPICIOUS_COMMAND_PATTERNS
    import re
    pattern_details = []
    for pattern, description, technique_id in SUSPICIOUS_COMMAND_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            pattern_details.append({
                "description": description,
                "mitre_technique": technique_id,
            })

    risk_level = _risk_from_match_count(len(pattern_details), prompt_injection)

    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info(
        "[tool] analyze_command | %d matches, risk=%s in %.1f ms",
        len(pattern_details), risk_level, elapsed_ms,
    )

    return {
        "command_preview": command[:200] + ("..." if len(command) > 200 else ""),
        "matches": pattern_details,
        "mitre_techniques": mitre_techniques,
        "risk_level": risk_level,
        "prompt_injection_detected": prompt_injection,
        "execution_note": "This command was NOT executed. Analysis is regex-based only.",
        "confirmed_source": "Heuristic pattern matching (SUSPICIOUS_COMMAND_PATTERNS)",
    }
