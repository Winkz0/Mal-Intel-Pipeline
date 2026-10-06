"""
api.py
Anthropic Messages API engine.

- Model pin: claude-sonnet-5-5 (claude-sonnet-4-5 was deprecated 2026-09-30 and
  retires 2026-11-30).
- Sonnet 5.5 rejects temperature/top_p/top_k with a 400 and runs adaptive
  thinking by default, so none of those are sent; thinking tokens count against
  max_tokens, hence 16,000.
- The response's text is the concatenation of its `text` blocks; `thinking`
  blocks are kept in the raw response only. (The old code read content[0].text,
  which is a thinking block when thinking runs.)
- A max_tokens or refusal stop fails closed.
- Tools are never sent.
"""

import os

DEFAULT_MODEL = "claude-sonnet-5-5"
DEFAULT_MAX_TOKENS = 16_000

# Never sent: tools (untrusted input), sampling params (400 on Sonnet 5.5).
FORBIDDEN_PARAMS = frozenset({"tools", "tool_choice", "temperature", "top_p", "top_k"})

# What the model does with the parameters we leave unset (docs, checked 2026-10-05).
DEFAULTS_ASSUMED = {
    "thinking": "adaptive (model default; not sent)",
    "effort": "model default, high (not sent)",
}


class EngineConfigError(ValueError):
    pass


def extract_text(message) -> str:
    """Join the text blocks of a Messages API response, skipping thinking blocks."""
    parts = []
    for block in getattr(message, "content", None) or []:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "".join(parts)


class AnthropicEngine:
    id = "anthropic-api"

    def __init__(self, model: str = DEFAULT_MODEL, max_tokens: int = DEFAULT_MAX_TOKENS,
                 extra_params: dict = None, api_key: str = None, client=None):
        extra_params = dict(extra_params or {})
        bad = FORBIDDEN_PARAMS & set(extra_params)
        if bad:
            raise EngineConfigError(f"parameters not allowed for synthesis: {sorted(bad)}")
        if {"model", "max_tokens", "messages"} & set(extra_params):
            raise EngineConfigError("model/max_tokens/messages are set by the engine")
        self.model = model
        self.max_tokens = max_tokens
        self.extra_params = extra_params
        self._api_key = api_key
        self._client = client

    def build_request(self, prompt: str) -> dict:
        request = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            **self.extra_params,
        }
        assert not FORBIDDEN_PARAMS & set(request)
        return request

    def recorded_params(self) -> dict:
        """Parameters as sent, minus the prompt itself."""
        return {"max_tokens": self.max_tokens, **self.extra_params}

    def run(self, prompt: str):
        import anthropic

        from pipeline.llm_synthesis.engines import EngineResult

        res = EngineResult(
            engine_id=self.id,
            model_requested=self.model,
            params=self.recorded_params(),
            defaults_assumed=None if self.extra_params else dict(DEFAULTS_ASSUMED),
            sdk=f"anthropic {anthropic.__version__}",
        )

        client = self._client
        if client is None:
            api_key = self._api_key or os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                res.error = "ANTHROPIC_API_KEY not set"
                return res
            client = anthropic.Anthropic(api_key=api_key)

        try:
            message = client.messages.create(**self.build_request(prompt))
        except anthropic.APIError as e:
            res.error = f"Anthropic API error ({type(e).__name__}): {e}"
            return res
        except Exception as e:  # network, SDK validation, etc.
            res.error = f"Unexpected error calling the API ({type(e).__name__}): {e}"
            return res

        res.raw = message.model_dump(mode="json")
        res.model_reported = getattr(message, "model", None)
        res.response_id = getattr(message, "id", None)
        res.stop_reason = getattr(message, "stop_reason", None)
        usage = getattr(message, "usage", None)
        res.usage = usage.model_dump(mode="json") if usage is not None else None
        res.text = extract_text(message)

        if res.stop_reason == "max_tokens":
            res.error = f"response truncated at max_tokens={self.max_tokens}"
        elif res.stop_reason == "refusal":
            res.error = "model refused the request"
        elif not res.text.strip():
            res.error = "response contained no text blocks"
        return res
