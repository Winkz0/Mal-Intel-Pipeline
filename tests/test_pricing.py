import pytest

from pipeline.llm_synthesis import prompt_builder
from pipeline.llm_synthesis.pricing import ESTIMATED_OUTPUT_TOKENS, actual_cost, estimate_cost


def test_sonnet_55_estimate():
    e = estimate_cost("x" * 4000, "claude-sonnet-5-5")
    assert e["estimated_input_tokens"] == 1000
    assert e["estimated_cost_usd"] == pytest.approx(1000 / 1e6 * 2 + ESTIMATED_OUTPUT_TOKENS / 1e6 * 10)


def test_batch_halves_cost():
    full = estimate_cost("x" * 4000, "claude-haiku-4-5")["estimated_cost_usd"]
    half = estimate_cost("x" * 4000, "claude-haiku-4-5", batch=True)["estimated_cost_usd"]
    assert half == pytest.approx(full / 2)


def test_unknown_model_gives_none_not_a_guess():
    assert estimate_cost("x", "claude-mystery-9")["estimated_cost_usd"] is None
    assert actual_cost({"input_tokens": 1, "output_tokens": 1}, "claude-mystery-9") is None


def test_dry_run_is_free():
    e = estimate_cost("x" * 4000, "dry-run")
    assert e["estimated_cost_usd"] == 0 and e["estimated_output_tokens"] == 0


def test_actual_cost_from_usage():
    assert actual_cost({"input_tokens": 2_000_000, "output_tokens": 1_000_000}, "claude-opus-5-5") == 28.0
    assert actual_cost(None, "claude-sonnet-5-5") is None


def test_old_import_path_still_works():
    assert prompt_builder.estimate_cost is estimate_cost
