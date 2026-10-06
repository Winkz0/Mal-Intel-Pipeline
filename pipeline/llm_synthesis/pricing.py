"""
pricing.py
Per-model API prices for cost estimates (checkpoint #2) and for the actual cost
recorded in each run manifest.

Prices are USD per million tokens, standard (non-batch) rates, from
https://platform.claude.com/docs/en/about-claude/pricing as checked 2026-10-05.
Batch API is 50% off. Thinking tokens bill as output tokens. Re-check before
the benchmark; a model missing here gets cost None, not a guess.
"""

PRICES_CHECKED = "2026-10-05"
BATCH_DISCOUNT = 0.5

# model -> (input $/MTok, output $/MTok)
PRICES_PER_MTOK = {
    "claude-opus-5-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-haiku-4-5-20251001": (1.0, 5.0),
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-sonnet-4-5-20250929": (3.0, 15.0),
}

# Rough output budget per synthesis: ~2k tokens of JSON plus adaptive thinking.
# Replace with measured manifest usage once real runs exist.
ESTIMATED_OUTPUT_TOKENS = 6_000


def estimate_tokens(prompt: str) -> int:
    """Rough token estimate — ~4 chars per token for English text."""
    return len(prompt) // 4


def _price(model: str, batch: bool):
    p = PRICES_PER_MTOK.get(model)
    if p is None:
        return None
    mult = BATCH_DISCOUNT if batch else 1.0
    return p[0] * mult, p[1] * mult


def estimate_cost(prompt: str, model: str = "claude-sonnet-5-5", batch: bool = False) -> dict:
    """Pre-call estimate shown at checkpoint #2. Dry runs and the Desktop inbox
    (subscription, no per-call bill) cost nothing at the margin."""
    free = model in ("dry-run", "desktop-mcp")
    input_tokens = estimate_tokens(prompt)
    output_tokens = 0 if model == "dry-run" else ESTIMATED_OUTPUT_TOKENS
    price = (0.0, 0.0) if free else _price(model, batch)
    cost = None
    if price is not None:
        cost = round(input_tokens / 1e6 * price[0] + output_tokens / 1e6 * price[1], 6)
    return {
        "model": model,
        "batch": batch,
        "estimated_input_tokens": input_tokens,
        "estimated_output_tokens": output_tokens,
        "estimated_cost_usd": cost,
        "prices_checked": PRICES_CHECKED,
    }


def actual_cost(usage: dict, model: str, batch: bool = False):
    """Cost from a response's usage block (input + output tokens). None if unknown."""
    if not usage or not model:
        return None
    price = _price(model, batch)
    if price is None:
        return None
    inp = usage.get("input_tokens") or 0
    out = usage.get("output_tokens") or 0
    return round(inp / 1e6 * price[0] + out / 1e6 * price[1], 6)
