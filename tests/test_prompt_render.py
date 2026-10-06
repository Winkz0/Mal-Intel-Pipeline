import hashlib
import random

import pytest

from pipeline.llm_synthesis import prompt_builder
from pipeline.llm_synthesis.bundle import DEFAULT_CAPS, LEGACY_CAPS, build_bundle
from pipeline.llm_synthesis.legacy_prompt import legacy_build_synthesis_prompt
from pipeline.llm_synthesis.prompt_builder import (
    PromptTooLarge,
    TemplateError,
    build_synthesis_prompt,
    load_template,
    render,
)
from tests.fixtures import edge_analyses, random_analysis, rich_analysis

NOTE = "Analyst: compare with $PREV and {last week}.\nSecond line."


def legacy(a, notes=""):
    p = legacy_build_synthesis_prompt(a)
    return p + f"\n\n## Analyst Notes\n{notes}" if notes else p


def v1(a, notes=""):
    return render(build_bundle(a, caps=LEGACY_CAPS, analyst_notes=notes), "synthesis_v1").prompt


CASES = {"rich": rich_analysis(), **edge_analyses()}


@pytest.mark.parametrize("name", sorted(CASES))
@pytest.mark.parametrize("notes", ["", NOTE])
def test_v1_parity_with_legacy_builder(name, notes):
    a = CASES[name]
    assert v1(a, notes) == legacy(a, notes)


def test_v1_parity_fuzz():
    rng = random.Random(20261005)
    for _ in range(300):
        a = random_analysis(rng)
        notes = NOTE if rng.random() < 0.3 else ""
        assert v1(a, notes) == legacy(a, notes)


def test_back_compat_wrapper_matches_legacy():
    a = rich_analysis()
    assert build_synthesis_prompt(a) == legacy_build_synthesis_prompt(a)


def test_default_caps_only_differ_by_string_shortening():
    a = rich_analysis()
    p = render(build_bundle(a, caps=DEFAULT_CAPS)).prompt
    assert "L" * 256 + "... [TRUNCATED]" in p
    assert "L" * 257 not in p


def test_render_reports_template_and_prompt_hashes():
    r = render(build_bundle(rich_analysis()), "synthesis_v1")
    raw = (prompt_builder.TEMPLATE_DIR / "synthesis_v1.txt").read_bytes()
    assert r.template_sha256 == hashlib.sha256(raw).hexdigest()
    assert r.prompt_sha256 == hashlib.sha256(r.prompt.encode("utf-8")).hexdigest()
    assert r.template_id == "synthesis_v1"


def test_attacker_strings_are_inserted_literally():
    a = {"static_analysis": {"floss": {"notable_strings": ["$sha256", "${family}"]}}}
    p = render(build_bundle(a)).prompt
    assert "  - $sha256\n  - ${family}" in p


def test_unknown_template_rejected():
    with pytest.raises(TemplateError):
        render(build_bundle({}), "synthesis_v99")


def test_crlf_template_rejected(tmp_path, monkeypatch):
    raw = (prompt_builder.TEMPLATE_DIR / "synthesis_v1.txt").read_bytes()
    (tmp_path / "synthesis_v1.txt").write_bytes(raw.replace(b"\n", b"\r\n"))
    monkeypatch.setattr(prompt_builder, "TEMPLATE_DIR", tmp_path)
    with pytest.raises(TemplateError, match="CR"):
        load_template("synthesis_v1")


def test_oversized_prompt_fails_closed(monkeypatch):
    monkeypatch.setattr(prompt_builder, "MAX_PROMPT_CHARS", 1000)
    with pytest.raises(PromptTooLarge):
        render(build_bundle(rich_analysis()))


def test_template_file_has_no_stray_placeholders():
    text, _ = load_template("synthesis_v1")
    # every $name must be a field the v1 formatter supplies
    import re
    names = set(re.findall(r"\$([_a-z][_a-z0-9]*)", text))
    assert names == set(prompt_builder._fields_v1(build_bundle({})))
