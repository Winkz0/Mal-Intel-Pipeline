"""
dry_run.py
Placeholder engine: no network, canned output in the report-compatible shape.
The "[DRY RUN]" markers make rule_extractor skip rule files.
The placeholder validates against both output schemas.
"""

import json

# Valid under both output schemas, so dry runs exercise validation too. Confidence
# fields must be a schema enum; "low" plus the [DRY RUN] markers is the placeholder.
DRY_RUN_SYNTHESIS = {
    "verdict": {"classification": "unknown", "family": None, "confidence": "low"},
    "ttp_mapping": {"narrative": "[DRY RUN]", "techniques": [], "confidence": "low", "reasoning": "[DRY RUN]"},
    "yara_rule": {"rule": "[DRY RUN]", "confidence": "low", "reasoning": "[DRY RUN]"},
    "sigma_rule": {"rule": "[DRY RUN]", "log_sources": [], "crowdstrike_notes": "",
                   "splunk_notes": "", "confidence": "low", "reasoning": "[DRY RUN]"},
    "technical_report": {"executive_summary": "[DRY RUN]", "technical_summary": "",
                         "key_indicators": [], "recommended_actions": []},
    "iocs": {"ips": [], "domains": [], "urls": [], "hashes": [], "commands": []},
    "manipulation_observed": {"detected": False, "evidence": []},
}


class DryRunEngine:
    id = "dry-run"

    def run(self, prompt: str):
        from pipeline.llm_synthesis.engines import EngineResult
        return EngineResult(
            engine_id=self.id,
            text=json.dumps(DRY_RUN_SYNTHESIS),
            stop_reason="dry_run",
        )
