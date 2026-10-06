"""
engines
M13 v2 (D2.2): synthesis engines behind one interface.

An engine takes rendered prompt text and returns an EngineResult. It never
parses or validates the model's JSON (synthesizer.run_synthesis does that), and
no engine is ever given tools: synthesis input contains attacker-controlled
strings.

Engines:
    api      Anthropic Messages API (anthropic SDK), synchronous
    dry-run  canned placeholder output, no network
    desktop  Claude Desktop inbox via the synthesis-queue MCP server (D2.6)
"""

from dataclasses import dataclass, field


@dataclass
class EngineResult:
    engine_id: str
    text: str | None = None
    raw: dict | None = None
    model_requested: str | None = None
    model_reported: str | None = None
    params: dict = field(default_factory=dict)
    defaults_assumed: dict | None = None
    usage: dict | None = None
    response_id: str | None = None
    stop_reason: str | None = None
    sdk: str | None = None
    error: str | None = None


ENGINE_IDS = ("api", "dry-run")


def get_engine(engine_id: str, **kwargs):
    if engine_id == "api":
        from pipeline.llm_synthesis.engines.api import AnthropicEngine
        return AnthropicEngine(**kwargs)
    if engine_id == "dry-run":
        from pipeline.llm_synthesis.engines.dry_run import DryRunEngine
        return DryRunEngine()
    raise ValueError(f"unknown engine: {engine_id} (expected one of {', '.join(ENGINE_IDS)})")
