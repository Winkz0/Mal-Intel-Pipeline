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
    Mapped perfectly to the normalized JSON schema.
    """
    score = 0
    
    # 1. Open the parent block
    static_analysis = analysis.get("static_analysis", {})
    
    # 2. Capa Scoring (Safely handles missing Capa blocks if a tool fails)
    capa = static_analysis.get("capa", {})
    # Fallback in case Capa is flattened or nested
    capa_summary = capa.get("summary", capa) 
    capa_ttps = capa_summary.get("total_attack_ttps", 0)
    score += capa_ttps * 10
    score += capa_summary.get("total_capabilities", 0) * 2
    
    # 3. FLOSS Scoring
    floss = static_analysis.get("floss", {})
    # Directly accesses the flattened list
    notable_strings = floss.get("notable_strings", [])
    score += len(notable_strings) * 5
    
    # 4. PEfile Scoring
    pe = static_analysis.get("pefile", {})
    # Directly accesses the flattened list
    suspicious_imports = pe.get("suspicious_imports", [])
    score += len(suspicious_imports) * 5
    
    # DEBUG: Print exactly what the scoring engine found
    print(f"      [DEBUG] Triage Engine -> Capa TTPs: {capa_ttps} | Notable Strings: {len(notable_strings)} | Suspicious Imports: {len(suspicious_imports)}")
    
    final_score = min(score, 100)
    
    return {
        "score": final_score,
        "needs_dynamic": final_score >= 50
    }