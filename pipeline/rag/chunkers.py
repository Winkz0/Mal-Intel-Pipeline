"""
chunkers.py
Document-type-aware chunking for the RAG indexer.
Each chunker returns a list of dicts: {"text": str, "metadata": dict}
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def chunk_analysis(path: Path) -> list[dict]:
    """
    Splits a .analysis.json into logical sections:
    - sample metadata
    - capabilities (capa)
    - notable strings (floss)
    - IOC candidates
    - PE summary (pefile)
    - file identification (diec)
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    sha256 = data.get("sample", {}).get("sha256", "unknown")
    family = data.get("sample", {}).get("malware_family", "unknown")
    base_meta = {"sha256": sha256, "family": family, "doc_type": "analysis", "source_file": path.name}
    chunks = []

    # Sample overview
    sample = data.get("sample", {})
    overview = (
        f"Sample: {sample.get('file_name', 'unknown')} | "
        f"SHA256: {sha256} | Family: {family} | "
        f"Type: {sample.get('file_type', 'unknown')} | "
        f"Tags: {', '.join(sample.get('tags', []))}"
    )
    chunks.append({"text": overview, "metadata": {**base_meta, "section": "overview"}})

    # Capabilities
    static = data.get("static_analysis", {})
    capa = static.get("capa", {})
    capabilities = capa.get("capabilities", [])
    attack_ttps = capa.get("attack_ttps", [])

    if capabilities:
        cap_text = f"Capabilities for {family} ({sha256[:16]}): " + ", ".join(capabilities)
        chunks.append({"text": cap_text, "metadata": {**base_meta, "section": "capabilities"}})

    if attack_ttps:
        ttp_lines = [f"[{t.get('id','')}] {t.get('technique','')} ({t.get('tactic','')})" for t in attack_ttps]
        ttp_text = f"ATT&CK TTPs for {family} ({sha256[:16]}): " + "; ".join(ttp_lines)
        chunks.append({"text": ttp_text, "metadata": {**base_meta, "section": "attack_ttps"}})

    # Notable strings
    floss = static.get("floss", {})
    notable = floss.get("notable_strings", [])
    if notable:
        str_text = f"Notable strings for {family} ({sha256[:16]}): " + " | ".join(notable[:80])
        chunks.append({"text": str_text, "metadata": {**base_meta, "section": "strings"}})

    # IOCs
    iocs = data.get("ioc_candidates", {})
    ioc_parts = []
    for ioc_type in ["ips", "urls", "commands", "registry_keys"]:
        items = iocs.get(ioc_type, [])
        if items:
            ioc_parts.append(f"{ioc_type}: {', '.join(items[:30])}")
    if ioc_parts:
        ioc_text = f"IOC candidates for {family} ({sha256[:16]}): " + " | ".join(ioc_parts)
        chunks.append({"text": ioc_text, "metadata": {**base_meta, "section": "iocs"}})

    # PE summary
    pe = static.get("pefile", {})
    if pe.get("architecture"):
        pe_parts = [
            f"Architecture: {pe.get('architecture')}",
            f"Imphash: {pe.get('imphash', 'n/a')}",
            f"Compile time: {pe.get('compile_timestamp', 'n/a')}",
        ]
        suspicious = pe.get("suspicious_imports", [])
        if suspicious:
            pe_parts.append(f"Suspicious imports: {', '.join(suspicious[:20])}")
        high_ent = pe.get("high_entropy_sections", [])
        if high_ent:
            pe_parts.append(f"High entropy sections: {', '.join(high_ent)}")
        pe_text = f"PE analysis for {family} ({sha256[:16]}): " + " | ".join(pe_parts)
        chunks.append({"text": pe_text, "metadata": {**base_meta, "section": "pe_summary"}})

    # DiE
    diec = static.get("diec", {})
    if diec.get("file_type"):
        die_parts = [
            f"File type: {diec.get('file_type')}",
            f"Compiler: {diec.get('compiler', 'n/a')}",
            f"Packer: {diec.get('packer', 'none')}",
            f"Is packed: {diec.get('is_packed', False)}",
        ]
        die_text = f"DiE identification for {family} ({sha256[:16]}): " + " | ".join(die_parts)
        chunks.append({"text": die_text, "metadata": {**base_meta, "section": "diec"}})

    return chunks


def chunk_synthesis(path: Path) -> list[dict]:
    """
    Splits a .synthesis.json into sections:
    - executive summary
    - technical summary
    - TTP narrative + mapped techniques
    - YARA rule + reasoning
    - Sigma rule + reasoning
    - recommended actions
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    sample = raw.get("sample", {})
    sha256 = sample.get("sha256", "unknown")
    family = sample.get("malware_family", "unknown")
    syn = raw.get("synthesis", raw)
    base_meta = {"sha256": sha256, "family": family, "doc_type": "synthesis", "source_file": path.name}
    chunks = []

    # Executive summary
    tech = syn.get("technical_report", {})
    exec_summary = tech.get("executive_summary", "")
    if exec_summary:
        chunks.append({
            "text": f"Executive summary for {family} ({sha256[:16]}): {exec_summary}",
            "metadata": {**base_meta, "section": "executive_summary"}
        })

    # Technical summary
    tech_summary = tech.get("technical_summary", "")
    if tech_summary:
        chunks.append({
            "text": f"Technical analysis of {family} ({sha256[:16]}): {tech_summary}",
            "metadata": {**base_meta, "section": "technical_summary"}
        })

    # TTP narrative
    ttp = syn.get("ttp_mapping", {})
    narrative = ttp.get("narrative", "")
    if narrative:
        techniques = ttp.get("techniques", [])
        tech_lines = [f"[{t.get('id','')}] {t.get('name','')} - {t.get('evidence','')}" for t in techniques]
        ttp_text = f"TTP analysis for {family} ({sha256[:16]}): {narrative}\nMapped techniques: " + "; ".join(tech_lines)
        chunks.append({"text": ttp_text, "metadata": {**base_meta, "section": "ttp_mapping"}})

    # YARA rule
    yara = syn.get("yara_rule", {})
    yara_rule = yara.get("rule", "")
    if yara_rule and yara_rule != "[DRY RUN]":
        yara_text = (
            f"YARA rule for {family} ({sha256[:16]}) "
            f"[confidence: {yara.get('confidence', 'unknown')}]: "
            f"{yara.get('reasoning', '')} | Rule: {yara_rule}"
        )
        chunks.append({"text": yara_text, "metadata": {**base_meta, "section": "yara_rule"}})

    # Sigma rule
    sigma = syn.get("sigma_rule", {})
    sigma_rule = sigma.get("rule", "")
    if sigma_rule and sigma_rule != "[DRY RUN]":
        sigma_text = (
            f"Sigma rule for {family} ({sha256[:16]}) "
            f"[confidence: {sigma.get('confidence', 'unknown')}]: "
            f"{sigma.get('reasoning', '')} | "
            f"CrowdStrike: {sigma.get('crowdstrike_notes', '')} | "
            f"Splunk: {sigma.get('splunk_notes', '')} | "
            f"Rule: {sigma_rule}"
        )
        chunks.append({"text": sigma_text, "metadata": {**base_meta, "section": "sigma_rule"}})

    # Key indicators + recommended actions
    indicators = tech.get("key_indicators", [])
    actions = tech.get("recommended_actions", [])
    if indicators or actions:
        parts = []
        if indicators:
            parts.append(f"Key IOCs: {', '.join(indicators[:20])}")
        if actions:
            parts.append(f"Recommended actions: {'; '.join(actions)}")
        chunks.append({
            "text": f"Indicators and actions for {family} ({sha256[:16]}): " + " | ".join(parts),
            "metadata": {**base_meta, "section": "indicators_actions"}
        })

    return chunks


def chunk_delta(path: Path) -> list[dict]:
    """Splits a .delta.json into a summary chunk per comparison."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    sha256 = data.get("sha256", "unknown")
    family = data.get("family", "unknown")
    base_meta = {"sha256": sha256, "family": family, "doc_type": "delta", "source_file": path.name}
    chunks = []

    comparisons = data.get("comparisons", [])
    for comp in comparisons[:10]:  # Cap to top 10 matches
        parts = [
            f"Delta: {family} ({sha256[:16]}) vs {comp.get('compared_family','unknown')} ({comp.get('compared_sha256','')[:16]})",
            f"Overlap score: {comp.get('overlap_score', 0)}",
            f"Same family: {comp.get('same_family', False)}",
            f"Same imphash: {comp.get('same_imphash', False)}",
        ]
        shared_ttps = comp.get("shared_attack_ttps", [])
        if shared_ttps:
            parts.append(f"Shared TTPs: {', '.join(shared_ttps)}")
        shared_caps = comp.get("shared_capabilities", [])
        if shared_caps:
            parts.append(f"Shared capabilities: {', '.join(shared_caps[:15])}")
        shared_strings = comp.get("shared_notable_strings", [])
        if shared_strings:
            parts.append(f"Shared strings: {', '.join(shared_strings[:15])}")

        chunks.append({"text": " | ".join(parts), "metadata": {**base_meta, "section": "delta_comparison"}})

    return chunks


def chunk_yara_file(path: Path) -> list[dict]:
    """Index a standalone .yar file as a single chunk."""
    text = path.read_text(encoding="utf-8")
    sha256 = path.stem.split(".")[0]
    return [{
        "text": f"YARA rule file ({sha256[:16]}): {text}",
        "metadata": {"sha256": sha256, "doc_type": "yara_file", "section": "full_rule", "source_file": path.name}
    }]


def chunk_sigma_file(path: Path) -> list[dict]:
    """Index a standalone .yml Sigma rule as a single chunk."""
    text = path.read_text(encoding="utf-8")
    sha256 = path.stem.split(".")[0]
    return [{
        "text": f"Sigma rule file ({sha256[:16]}): {text}",
        "metadata": {"sha256": sha256, "doc_type": "sigma_file", "section": "full_rule", "source_file": path.name}
    }]