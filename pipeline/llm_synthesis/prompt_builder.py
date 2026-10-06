"""
prompt_builder.py
Renders a synthesis bundle (bundle.py) into prompt text with a versioned template.

Templates live in pipeline/llm_synthesis/templates/<template_id>.txt and use
string.Template `$name` placeholders, so the JSON braces in the output spec need
no escaping. Each template ID has a field formatter here; the template's SHA-256
(raw file bytes) is reported with every render so runs can record exactly what
was used.

synthesis_v1 reproduces the pre-M13-v2 prompt byte for byte when the bundle is
built with bundle.LEGACY_CAPS (see legacy_prompt.py and
scripts/check_template_parity.py).
"""

import hashlib
from pathlib import Path
from string import Template
from typing import NamedTuple

from pipeline.llm_synthesis.bundle import LEGACY_CAPS, build_bundle

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
DEFAULT_TEMPLATE = "synthesis_v1"

# Fail closed instead of sending (and retrying) an oversized prompt. With the
# default caps a normal bundle renders to well under 50k characters.
MAX_PROMPT_CHARS = 200_000


class TemplateError(ValueError):
    """Unknown template or a template file that can't be used as-is."""


class PromptTooLarge(ValueError):
    """Rendered prompt exceeds MAX_PROMPT_CHARS."""


class Rendered(NamedTuple):
    prompt: str
    template_id: str
    template_sha256: str
    prompt_sha256: str


# ── templates ───────────────────────────────────────────────────────────────

def load_template(template_id: str) -> tuple[str, str]:
    """
    Return (template_text, sha256_of_file_bytes).
    One trailing LF is stripped so the file can end with a normal newline.
    CR bytes are rejected: a CRLF checkout would silently change the prompt.
    """
    if template_id not in _FORMATTERS:
        raise TemplateError(f"unknown template: {template_id}")
    raw = (TEMPLATE_DIR / f"{template_id}.txt").read_bytes()
    if b"\r" in raw:
        raise TemplateError(f"{template_id}.txt has CR line endings; expected LF only")
    text = raw.decode("utf-8")
    if text.endswith("\n"):
        text = text[:-1]
    return text, hashlib.sha256(raw).hexdigest()


def _bullets(items, fmt, empty: str) -> str:
    return "\n".join(fmt(x) for x in items) or empty


def _fields_v1(b: dict) -> dict:
    s, d, p, f, c, i = (b["sample"], b["diec"], b["pefile"], b["floss"], b["capa"], b["iocs"])
    return {
        "sha256": f"{s['sha256']}",
        "file_name": f"{s['file_name']}",
        "file_type": f"{s['file_type']}",
        "detected_type": f"{d['file_type']}",
        "family": f"{s['malware_family']}",
        "tags": ", ".join(s["tags"]) or "none",
        "architecture": f"{p['architecture']}",
        "compiler": f"{d['compiler']}",
        "packer": f"{d['packer']}",
        "is_packed": f"{d['is_packed']}",
        "compile_time": f"{p['compile_timestamp']}",
        "imphash": f"{p['imphash']}",
        "total_static": f"{f['total_static']}",
        "total_decoded": f"{f['total_decoded']}",
        "notable_strings": _bullets(f["notable_strings"], lambda x: f"  - {x}", "  none"),
        "capabilities": _bullets(
            c["capabilities"], lambda x: f"  - {x}",
            "  none detected (file type may be unsupported by Capa)"),
        "attack_ttps": _bullets(
            c["attack_ttps"],
            lambda t: f"  - [{t.get('id','')}] {t.get('technique','')} ({t.get('tactic','')})",
            "  none mapped"),
        "mbc_behaviors": _bullets(
            c["mbc_behaviors"],
            lambda m: f"  - {m.get('objective','')}: {m.get('behavior','')}",
            "  none mapped"),
        "suspicious_imports": _bullets(
            p["suspicious_imports"], lambda x: f"  - {x}",
            "  none (not a PE or no suspicious imports)"),
        "high_entropy": _bullets(p["high_entropy_sections"], lambda x: f"  - {x}", "  none"),
        "ips": ", ".join(i["ips"]) or "none",
        "urls": ", ".join(i["urls"]) or "none",
        "commands": ", ".join(i["commands"]) or "none",
    }


def _notes_v1(b: dict) -> str:
    notes = b.get("analyst_notes") or ""
    return f"\n\n## Analyst Notes\n{notes}" if notes else ""


# template_id -> (field formatter, trailer)
_FORMATTERS = {
    "synthesis_v1": (_fields_v1, _notes_v1),
}


def available_templates() -> list[str]:
    return sorted(_FORMATTERS)


# ── render ──────────────────────────────────────────────────────────────────

def render(bundle: dict, template_id: str = DEFAULT_TEMPLATE) -> Rendered:
    """Render a bundle with a versioned template. Raises PromptTooLarge."""
    text, template_sha = load_template(template_id)
    fields, trailer = _FORMATTERS[template_id]
    prompt = Template(text).substitute(fields(bundle)) + trailer(bundle)
    if len(prompt) > MAX_PROMPT_CHARS:
        raise PromptTooLarge(
            f"rendered prompt is {len(prompt):,} chars (limit {MAX_PROMPT_CHARS:,})")
    prompt_sha = hashlib.sha256(prompt.encode("utf-8", "surrogatepass")).hexdigest()
    return Rendered(prompt, template_id, template_sha, prompt_sha)


def build_synthesis_prompt(analysis: dict) -> str:
    """Back-compat wrapper: the legacy prompt, via bundle + synthesis_v1."""
    return render(build_bundle(analysis, caps=LEGACY_CAPS), "synthesis_v1").prompt


# ── cost estimate (repriced per model in D2.2) ──────────────────────────────

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
