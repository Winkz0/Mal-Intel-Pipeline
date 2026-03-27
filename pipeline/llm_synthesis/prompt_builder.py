"""
prompt_builder.py
Constructs structured prompts from M6 analysis JSON for Claude API synthesis.
Designed to produce analyst-quality output, not generic summaries.
"""

import json
from pathlib import Path


def build_synthesis_prompt(analysis: dict) -> str:
    """
    Build the main synthesis prompt from a normalized analysis document.
    Structures the context so Claude can produce actionable intel output.
    """
    sample = analysis.get("sample", {})
    static = analysis.get("static_analysis", {})
    iocs = analysis.get("ioc_candidates", {})

    sha256 = sample.get("sha256", "unknown")
    family = sample.get("malware_family", "unknown")
    file_type = sample.get("file_type", "unknown")
    file_name = sample.get("file_name", "unknown")
    tags = ", ".join(sample.get("tags", [])) or "none"

    # diec findings
    diec = static.get("diec", {})
    detected_type = diec.get("file_type") or "unknown"
    compiler = diec.get("compiler") or "unknown"
    packer = diec.get("packer") or "none detected"
    is_packed = diec.get("is_packed", False)

    # pefile findings
    pe = static.get("pefile", {})
    is_pe = pe.get("is_pe", False)
    architecture = pe.get("architecture") or "unknown"
    compile_time = pe.get("compile_timestamp") or "unknown"
    imphash = pe.get("imphash") or "n/a"
    suspicious_imports = pe.get("suspicious_imports", [])
    high_entropy = pe.get("high_entropy_sections", [])

    # FLOSS findings
    floss = static.get("floss", {})
    notable_strings = floss.get("notable_strings", [])
    total_static = floss.get("total_static", 0)
    total_decoded = floss.get("total_decoded", 0)

    # Capa findings
    capa = static.get("capa", {})
    capabilities = capa.get("capabilities", [])
    attack_ttps = capa.get("attack_ttps", [])
    mbc_behaviors = capa.get("mbc_behaviors", [])

    # IOC candidates
    ips = iocs.get("ips", [])
    urls = iocs.get("urls", [])
    commands = iocs.get("commands", [])

    prompt = f"""You are a senior malware analyst. Analyze the following static analysis findings and produce structured threat intelligence output.

## Sample Metadata
- SHA256: {sha256}
- File Name: {file_name}
- File Type: {file_type} (detected: {detected_type})
- Suspected Family: {family}
- Tags: {tags}

## File Characteristics
- Architecture: {architecture}
- Compiler/Package: {compiler}
- Packer: {packer}
- Is Packed: {is_packed}
- Compile Timestamp: {compile_time}
- Import Hash: {imphash}

## String Analysis (FLOSS)
- Total Static Strings: {total_static}
- Decoded Strings: {total_decoded}
- Notable Strings:
{chr(10).join(f"  - {s}" for s in notable_strings[:50]) or "  none"}

## Detected Capabilities (Capa)
{chr(10).join(f"  - {c}" for c in capabilities[:30]) or "  none detected (file type may be unsupported by Capa)"}

## MITRE ATT&CK TTPs
{chr(10).join(f"  - [{t.get('id','')}] {t.get('technique','')} ({t.get('tactic','')})" for t in attack_ttps) or "  none mapped"}

## MBC Behaviors
{chr(10).join(f"  - {b.get('objective','')}: {b.get('behavior','')}" for b in mbc_behaviors) or "  none mapped"}

## Suspicious Imports
{chr(10).join(f"  - {i}" for i in suspicious_imports[:30]) or "  none (not a PE or no suspicious imports)"}

## High Entropy Sections
{chr(10).join(f"  - {s}" for s in high_entropy) or "  none"}

## IOC Candidates
- IPs: {', '.join(ips[:20]) or 'none'}
- URLs: {', '.join(urls[:20]) or 'none'}
- Commands: {', '.join(commands[:20]) or 'none'}

---

Produce the following output in valid JSON format with these exact keys:

{{
  "ttp_mapping": {{
    "narrative": "2-3 paragraph analysis of observed TTPs and behavioral patterns",
    "techniques": [
      {{"id": "TXXXX", "name": "technique name", "tactic": "tactic", "evidence": "what in the sample supports this"}}
    ],
    "confidence": "high|medium|low",
    "reasoning": "why you assigned this confidence level"
  }},
  "yara_rule": {{
    "rule": "complete YARA rule as a string",
    "confidence": "high|medium|low",
    "reasoning": "explanation of string/pattern selections and why they are distinctive"
  }},
  "sigma_rule": {{
    "rule": "complete Sigma rule in YAML format as a string",
    "log_sources": ["list of applicable log sources"],
    "crowdstrike_notes": "how this maps to CrowdStrike Falcon telemetry",
    "splunk_notes": "equivalent Splunk SPL search logic",
    "confidence": "high|medium|low",
    "reasoning": "explanation of detection logic"
  }},
  "technical_report": {{
    "executive_summary": "3-5 sentence non-technical summary for stakeholders",
    "technical_summary": "detailed technical findings narrative for analysts",
    "key_indicators": ["list of highest-confidence IOCs"],
    "recommended_actions": ["prioritized list of response/hunting actions"]
  }}
}}

Return only valid JSON. No preamble, no markdown code blocks, no explanation outside the JSON structure."""

    return prompt


def estimate_tokens(prompt: str) -> int:
    """Rough token estimate — ~4 chars per token for English text."""
    return len(prompt) // 4


def estimate_cost(prompt: str, model: str = "claude-sonnet-4-5") -> dict:
    """
    Estimate API cost before sending.
    Based on current Anthropic pricing for Sonnet.
    Input: $3/MTok, Output: $15/MTok
    """
    input_tokens = estimate_tokens(prompt)
    # Assume ~2000 output tokens for a full synthesis response
    output_tokens = 2000

    input_cost = (input_tokens / 1_000_000) * 3.0
    output_cost = (output_tokens / 1_000_000) * 15.0
    total_cost = input_cost + output_cost

    return {
        "model": model,
        "estimated_input_tokens": input_tokens,
        "estimated_output_tokens": output_tokens,
        "estimated_cost_usd": round(total_cost, 6),
    }