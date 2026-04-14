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
    """Calculates a triage score based on static analysis artifacts."""
    score = 0
    reasons = []

    capa = analysis.get("capa_result", {})
    
    # 1. Score Capabilities
    capabilities = capa.get("capabilities", [])
    for cap in capabilities:
        cap_lower = cap.lower()
        for risk_cap, points in HIGH_RISK_CAPABILITIES.items():
            if risk_cap in cap_lower:
                score += points
                reasons.append(f"Capability (+{points}): {cap}")
                
    # 2. Score ATT&CK Tactics
    attack_ttps = capa.get("attack", [])
    seen_tactics = set()
    for ttp in attack_ttps:
        tactic = ttp.get("tactic", "")
        # Only score a tactic once per sample to prevent inflation
        if tactic in HIGH_RISK_TACTICS and tactic not in seen_tactics:
            points = HIGH_RISK_TACTICS[tactic]
            score += points
            seen_tactics.add(tactic)
            reasons.append(f"Tactic (+{points}): {tactic}")

    # 3. Score String Obfuscation
    floss = analysis.get("floss_result", {})
    summary = floss.get("summary", {})
    total_static = summary.get("total_static", 0)
    notable = len(summary.get("notable", []))
    
    # If the file has very few static strings but high capabilities, it's heavily packed
    if total_static < 50 and len(capabilities) > 5:
        score += 25
        reasons.append("Anomaly (+25): Low static strings vs high capability (Packed/Obfuscated)")

    return {
        "score": score,
        "reasons": reasons,
        "needs_dynamic": score >= 50  # Our threshold for detonation
    }