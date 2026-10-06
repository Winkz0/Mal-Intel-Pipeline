"""API engine tests run through the real anthropic SDK client over a mocked HTTP
transport: they check the exact request body sent and parse real SDK types."""

import json

import anthropic
import httpx
import pytest

from pipeline.llm_synthesis.engines import get_engine
from pipeline.llm_synthesis.engines.api import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    AnthropicEngine,
    EngineConfigError,
    extract_text,
)
from pipeline.llm_synthesis.engines.dry_run import DRY_RUN_SYNTHESIS


def message_json(content, stop_reason="end_turn", model="claude-sonnet-5-5"):
    return {
        "id": "msg_test_01",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 1234, "output_tokens": 4321},
    }


THINK_THEN_TEXT = [
    {"type": "thinking", "thinking": "Considering the capa hits...", "signature": "sig"},
    {"type": "text", "text": '{"ttp_mapping": {"techniques": []}}'},
]


def engine_with(handler, **kw):
    seen = []

    def wrapped(request: httpx.Request):
        seen.append(json.loads(request.content))
        status, body = handler(request)
        return httpx.Response(status, json=body)

    client = anthropic.Anthropic(
        api_key="test-key", base_url="https://api.invalid", max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(wrapped)),
    )
    return AnthropicEngine(client=client, **kw), seen


def test_request_body_is_exactly_what_we_intend():
    eng, seen = engine_with(lambda r: (200, message_json(THINK_THEN_TEXT)))
    res = eng.run("PROMPT TEXT")
    assert res.error is None
    body = seen[0]
    assert body["model"] == DEFAULT_MODEL == "claude-sonnet-5-5"
    assert body["max_tokens"] == DEFAULT_MAX_TOKENS == 16000
    assert body["messages"] == [{"role": "user", "content": "PROMPT TEXT"}]
    for forbidden in ("tools", "tool_choice", "temperature", "top_p", "top_k", "thinking"):
        assert forbidden not in body


def test_thinking_blocks_skipped_text_blocks_joined():
    content = [THINK_THEN_TEXT[0], {"type": "text", "text": '{"a": '}, {"type": "text", "text": "1}"}]
    eng, _ = engine_with(lambda r: (200, message_json(content)))
    res = eng.run("p")
    assert res.text == '{"a": 1}'
    assert res.raw["content"][0]["type"] == "thinking"  # kept in the raw record


def test_usage_model_id_and_params_recorded():
    eng, _ = engine_with(lambda r: (200, message_json(THINK_THEN_TEXT, model="claude-sonnet-5-5-20260601")))
    res = eng.run("p")
    assert res.usage["input_tokens"] == 1234 and res.usage["output_tokens"] == 4321
    assert res.model_requested == "claude-sonnet-5-5"
    assert res.model_reported == "claude-sonnet-5-5-20260601"
    assert res.response_id == "msg_test_01" and res.stop_reason == "end_turn"
    assert res.params == {"max_tokens": 16000}
    assert "thinking" in res.defaults_assumed and "effort" in res.defaults_assumed
    assert res.sdk.startswith("anthropic ")


@pytest.mark.parametrize("stop,needle", [("max_tokens", "truncated"), ("refusal", "refused")])
def test_bad_stop_reasons_fail_closed(stop, needle):
    eng, _ = engine_with(lambda r: (200, message_json(THINK_THEN_TEXT, stop_reason=stop)))
    res = eng.run("p")
    assert res.error and needle in res.error
    assert res.raw is not None  # still recorded


def test_thinking_only_response_is_an_error():
    eng, _ = engine_with(lambda r: (200, message_json([THINK_THEN_TEXT[0]])))
    assert "no text" in eng.run("p").error


@pytest.mark.parametrize("status", [400, 401, 429, 529])
def test_api_errors_are_captured_not_raised(status):
    eng, _ = engine_with(lambda r: (status, {"type": "error", "error": {"type": "x", "message": "nope"}}))
    res = eng.run("p")
    assert res.error.startswith("Anthropic API error") and res.raw is None


def test_missing_key_errors_before_any_request(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    res = AnthropicEngine().run("p")
    assert res.error == "ANTHROPIC_API_KEY not set"


@pytest.mark.parametrize("bad", [{"tools": []}, {"temperature": 0}, {"top_k": 5}, {"model": "x"}])
def test_forbidden_params_rejected_at_construction(bad):
    with pytest.raises(EngineConfigError):
        AnthropicEngine(extra_params=bad)


def test_allowed_extra_params_are_sent_and_recorded():
    eng, seen = engine_with(lambda r: (200, message_json(THINK_THEN_TEXT)),
                            extra_params={"output_config": {"effort": "medium"}})
    res = eng.run("p")
    assert seen[0]["output_config"] == {"effort": "medium"}
    assert res.params == {"max_tokens": 16000, "output_config": {"effort": "medium"}}
    assert res.defaults_assumed is None  # we pinned something; don't claim defaults


def test_extract_text_tolerates_odd_shapes():
    class B:
        def __init__(self, t, x=None):
            self.type, self.text = t, x

    class M:
        content = [B("thinking"), B("text", "a"), B("redacted_thinking"), B("text", "b")]

    assert extract_text(M()) == "ab"
    assert extract_text(object()) == ""


def test_dry_run_engine_is_canned_and_offline():
    res = get_engine("dry-run").run("anything")
    assert json.loads(res.text) == DRY_RUN_SYNTHESIS
    assert res.raw is None and res.usage is None and res.error is None


def test_unknown_engine():
    with pytest.raises(ValueError):
        get_engine("desktop")
