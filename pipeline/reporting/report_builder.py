"""
report_builder.py
Renders M7 synthesis JSON into human-readable Markdown reports.
Produces two audience-aware documents:
  - Technical report for analysts
  - Executive summary for stakeholders
"""

from pathlib import Path
from datetime import datetime, timezone
try:
    from pipeline.utils.naming import resolve
    _HAS_NAMING = True
except ImportError:
    _HAS_NAMING = False

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "output" / "reports"


def render_technical_report(synthesis: dict) -> str:
    """
    Full analyst-facing technical report in Markdown.
    Includes all static analysis findings, TTPs, rules, and IOCs.
    """
    sample = synthesis.get("sample", {})
    s = synthesis.get("synthesis", {})
    cost = synthesis.get("cost_estimate", {})

    ttp = s.get("ttp_mapping", {})
    yara = s.get("yara_rule", {})
    sigma = s.get("sigma_rule", {})
    report = s.get("technical_report", {})

    sha256 = sample.get("sha256", "unknown")
    family = sample.get("malware_family", "unknown")
    analyzed_at = synthesis.get("synthesized_at", "unknown")

    techniques = ttp.get("techniques", [])
    key_indicators = report.get("key_indicators", [])
    recommended_actions = report.get("recommended_actions", [])
    log_sources = sigma.get("log_sources", [])

    # Resolve human-readable alias if available
    alias = None
    if _HAS_NAMING:
        resolved = resolve(sha256)
        if resolved:
            alias = resolved["alias"]
    display_name = alias or family.title()

    md = f"""# Malware Analysis Report — {display_name()}\n\n"

**SHA256:** `{sha256}`
**File:** {sample.get("file_name", "unknown")}
**Type:** {sample.get("file_type", "unknown")}
**Family:** {family}
**Tags:** {", ".join(sample.get("tags", [])) or "none"}
**Analyzed:** {analyzed_at}
**Model:** {synthesis.get("model", "unknown")}

---

## Executive Summary

{report.get("executive_summary", "Not available.")}

---

## Technical Analysis

{report.get("technical_summary", "Not available.")}

---

## MITRE ATT&CK TTP Mapping

**Confidence:** {ttp.get("confidence", "unknown").upper()}
**Reasoning:** {ttp.get("reasoning", "")}

### Narrative

{ttp.get("narrative", "Not available.")}

### Mapped Techniques

| ID | Technique | Tactic | Evidence |
|----|-----------|--------|----------|
"""

    if techniques:
        for t in techniques:
            tid = t.get("id", "")
            name = t.get("name", "").replace("|", "/")
            tactic = t.get("tactic", "")
            evidence = t.get("evidence", "").replace("|", "/")
            md += f"| {tid} | {name} | {tactic} | {evidence} |\n"
    else:
        md += "| — | No techniques mapped | — | — |\n"

    md += f"""
---

## Key Indicators of Compromise

"""
    if key_indicators:
        for ioc in key_indicators:
            md += f"- `{ioc}`\n"
    else:
        md += "_No high-confidence IOCs identified._\n"

    md += f"""
---

## YARA Rule

**Confidence:** {yara.get("confidence", "unknown").upper()}
**Reasoning:** {yara.get("reasoning", "")}
```yara
{yara.get("rule", "# Rule not generated")}
```

---

## Sigma Rule

**Confidence:** {sigma.get("confidence", "unknown").upper()}
**Reasoning:** {sigma.get("reasoning", "")}

**Log Sources:** {", ".join(log_sources) or "none specified"}
```yaml
{sigma.get("rule", "# Rule not generated")}
```

### CrowdStrike Notes

{sigma.get("crowdstrike_notes", "Not available.")}

### Splunk Notes

{sigma.get("splunk_notes", "Not available.")}

---

## Recommended Actions

"""
    if recommended_actions:
        for i, action in enumerate(recommended_actions, 1):
            md += f"{i}. {action}\n"
    else:
        md += "_No actions recommended._\n"

    md += f"""
---

## Analysis Metadata

| Field | Value |
|-------|-------|
| Pipeline | Mal-Intel-Pipeline v1 |
| Model | {synthesis.get("model", "unknown")} |
| Est. Cost | ${cost.get("estimated_cost_usd", 0):.6f} USD |
| Dry Run | {synthesis.get("dry_run", False)} |
| Analyst Notes | {synthesis.get("analyst_notes", "none")} |
"""

    return md


def render_executive_summary(synthesis: dict) -> str:
    """
    Stakeholder-facing executive summary in Markdown.
    No technical jargon, focused on risk and recommended actions.
    """
    sample = synthesis.get("sample", {})
    s = synthesis.get("synthesis", {})

    ttp = s.get("ttp_mapping", {})
    yara = s.get("yara_rule", {})
    report = s.get("technical_report", {})

    family = sample.get("malware_family", "unknown")
    sha256 = sample.get("sha256", "unknown")
    analyzed_at = synthesis.get("synthesized_at", "unknown")
    confidence = ttp.get("confidence", "unknown").upper()
    recommended_actions = report.get("recommended_actions", [])
    
    # Resolve human-readable alias if available
    alias = None
    if _HAS_NAMING:
        resolved = resolve(sha256)
        if resolved:
            alias = resolved["alias"]
    display_name = alias or family.title()
    
    md = f"""# Executive Summary — {display_name()}\n\n" Threat Analysis

**Date:** {analyzed_at}
**Sample:** `{sha256[:16]}...`
**Threat Family:** {family.title()}
**Overall Confidence:** {confidence}

---

## What Was Found

{report.get("executive_summary", "Analysis did not produce a summary.")}

---

## Risk Assessment

| Category | Assessment |
|----------|------------|
| Threat Family | {family.title()} |
| Detection Confidence | {confidence} |
| YARA Rule Confidence | {yara.get("confidence", "unknown").upper()} |
| Recommended Priority | {"HIGH" if confidence == "HIGH" else "MEDIUM" if confidence == "MEDIUM" else "LOW"} |

---

## Recommended Actions

"""
    if recommended_actions:
        for i, action in enumerate(recommended_actions, 1):
            md += f"{i}. {action}\n"
    else:
        md += "_No specific actions recommended at this time._\n"

    md += """
---

_This report was generated by the Mal-Intel-Pipeline automated analysis system and reviewed by a human analyst. All findings should be validated before taking action._
"""

    return md


def save_report(content: str, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path