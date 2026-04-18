"""
triage.py
Triage Scoring Module.
Evaluates static analysis JSON to calculate a threat score.
Flags samples scoring >= 50 for dynamic detonation.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# High-value Capa capabilities that suggest advanced malware
HIGH_RISK_CAPABILITIES = {
    "reference anti-VM strings": 15,
    "check for virtualization tools": 15,
    "resolve APIs dynamically": 10,
    "extract resource via API": 10,
    "inject thread": 20,
    "hook window message": 15,
    "encrypt data using AES": 10,
    "obfuscated": 15,
    "contain packed code": 20
}

# Specific ATT&CK tactics we care deeply about for dynamic behavior
HIGH_RISK_TACTICS = {
    "Defense Evasion": 10,
    "Privilege Escalation": 15,
    "Credential Access": 15,
    "Discovery": 5
}

def calculate_score(analysis: dict) -> dict:
    """
    Calculates a triage score (0-100) based on static analysis indicators.
    Scores >= 50 flag the sample for dynamic detonation.
    """
    score = 0
    
    # 1. Capa Capability Scoring (High Weight)
    capa = analysis.get("capa_result", {}).get("summary", {})
    # 10 points for every mapped MITRE ATT&CK TTP
    score += capa.get("total_attack_ttps", 0) * 10
    # 2 points for every general malicious capability
    score += capa.get("total_capabilities", 0) * 2
    
    # 2. FLOSS String Extraction (Medium Weight)
    floss = analysis.get("floss_result", {}).get("summary", {})
    # 5 points for every notable/obfuscated string matched
    notable_strings = floss.get("notable", [])
    score += len(notable_strings) * 5
    
    # 3. PE Header Analysis (Medium Weight)
    pe = analysis.get("pefile_result", {}).get("summary", {})
    suspicious_imports = pe.get("suspicious_imports", [])
    if suspicious_imports:
        score += len(suspicious_imports) * 5
        
    # Cap the maximum score at 100
    final_score = min(score, 100)
    
    return {
        "score": final_score,
        "needs_dynamic": final_score >= 50
    }