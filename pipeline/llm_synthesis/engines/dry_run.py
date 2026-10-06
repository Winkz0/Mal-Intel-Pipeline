"""
dry_run.py
Placeholder engine: no network, canned output in the report-compatible shape.
The "[DRY RUN]" markers make rule_extractor skip rule files.
"""

import json

DRY_RUN_SYNTHESIS = {
    "ttp_mapping": {"narrative": "[DRY RUN]", "techniques": [], "confidence": "n/a", "reasoning": ""},
    "yara_rule": {"rule": "[DRY RUN]", "confidence": "n/a", "reasoning": ""},
    "sigma_rule": {"rule": "[DRY RUN]", "log_sources": [], "crowdstrike_notes": "",
                   "splunk_notes": "", "confidence": "n/a", "reasoning": ""},
    "technical_report": {"executive_summary": "[DRY RUN]", "technical_summary": "",
                         "key_indicators": [], "recommended_actions": []},
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
