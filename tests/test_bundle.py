import copy
import hashlib
import json

import pytest

from pipeline.llm_synthesis.bundle import (
    DEFAULT_CAPS,
    LEGACY_CAPS,
    TRUNCATION_MARKER,
    BundleError,
    build_bundle,
    bundle_id,
    canonical_bytes,
    load_bundle,
    save_bundle,
)
from tests.fixtures import edge_analyses, rich_analysis


def reorder(obj):
    """Same content, reversed key insertion order at every level."""
    if isinstance(obj, dict):
        return {k: reorder(obj[k]) for k in reversed(list(obj))}
    if isinstance(obj, list):
        return [reorder(x) for x in obj]
    return obj


def test_id_stable_across_key_order_and_reserialization():
    a = rich_analysis()
    b1 = build_bundle(a)
    b2 = build_bundle(reorder(a))
    b3 = json.loads(json.dumps(b1, indent=4))
    assert bundle_id(b1) == bundle_id(b2) == bundle_id(b3)


@pytest.mark.parametrize("mutate", [
    lambda a: a["sample"].__setitem__("malware_family", "Other"),
    lambda a: a["static_analysis"]["floss"]["notable_strings"].insert(0, "new"),
    lambda a: a["ioc_candidates"]["ips"].insert(0, "192.0.2.1"),
    lambda a: a["static_analysis"]["capa"]["attack_ttps"].pop(),
])
def test_any_input_change_changes_id(mutate):
    a = rich_analysis()
    before = bundle_id(build_bundle(a))
    mutate(a)
    assert bundle_id(build_bundle(a)) != before


def test_notes_and_caps_change_id():
    a = rich_analysis()
    base = bundle_id(build_bundle(a))
    assert bundle_id(build_bundle(a, analyst_notes="looks like a loader")) != base
    assert bundle_id(build_bundle(a, caps=LEGACY_CAPS)) != base


def test_source_hash_tracks_fields_outside_the_prompt():
    a = rich_analysis()
    b1 = build_bundle(a)
    a["static_analysis"]["floss"]["static_strings"] = ["not used by the prompt"]
    b2 = build_bundle(a)
    assert b1["source"]["analysis_sha256"] != b2["source"]["analysis_sha256"]


def test_caps_applied_and_recorded():
    b = build_bundle(rich_analysis(), caps=DEFAULT_CAPS)
    t = b["truncation"]
    assert len(b["floss"]["notable_strings"]) == 50 and t["notable_strings"]["total"] == 76
    assert len(b["capa"]["capabilities"]) == 30 and t["capabilities"] == {"total": 35, "kept": 30}
    assert len(b["pefile"]["suspicious_imports"]) == 30
    assert len(b["iocs"]["ips"]) == 20 and t["iocs.ips"] == {"total": 25, "kept": 20}
    assert b["caps"] == DEFAULT_CAPS


def test_max_str_len_shortens_with_marker():
    a = {"static_analysis": {"floss": {"notable_strings": ["x" * 300, "short", 42]}}}
    b = build_bundle(a, caps=DEFAULT_CAPS)
    s = b["floss"]["notable_strings"]
    assert s[0] == "x" * 256 + TRUNCATION_MARKER and s[1:] == ["short", 42]
    assert b["truncation"]["notable_strings"]["shortened"] == 1
    legacy = build_bundle(a, caps=LEGACY_CAPS)
    assert legacy["floss"]["notable_strings"][0] == "x" * 300
    assert "shortened" not in legacy["truncation"]["notable_strings"]


def test_input_not_mutated():
    a = rich_analysis()
    snapshot = copy.deepcopy(a)
    build_bundle(a, analyst_notes="n")
    assert a == snapshot


def test_canonical_bytes_are_ascii_even_with_unicode_and_lone_surrogates():
    b = build_bundle(edge_analyses()["non_pe"])
    data = canonical_bytes(b)
    data.decode("ascii")
    assert json.loads(data) == b


def test_non_finite_numbers_rejected():
    a = {"static_analysis": {"floss": {"total_static": float("nan")}}}
    with pytest.raises(BundleError, match="non-finite"):
        build_bundle(a)


@pytest.mark.parametrize("bad", [
    {"static_analysis": {"floss": {"notable_strings": "not a list"}}},
    {"static_analysis": {"capa": {"attack_ttps": ["T1055"]}}},
    {"sample": "nope"},
    [],
])
def test_malformed_shapes_rejected(bad):
    with pytest.raises(BundleError):
        build_bundle(bad)


@pytest.mark.parametrize("caps", [
    {**DEFAULT_CAPS, "extra": 1},
    {k: v for k, v in DEFAULT_CAPS.items() if k != "max_str_len"},
    {**DEFAULT_CAPS, "notable_strings": 0},
    {**DEFAULT_CAPS, "notable_strings": True},
])
def test_bad_caps_rejected(caps):
    with pytest.raises(BundleError):
        build_bundle(rich_analysis(), caps=caps)


def test_none_sections_and_lists_become_empty():
    a = {"sample": None, "static_analysis": {"floss": {"notable_strings": None}}}
    b = build_bundle(a)
    assert b["sample"]["sha256"] == "unknown" and b["floss"]["notable_strings"] == []


def test_save_is_content_addressed_atomic_and_idempotent(tmp_path):
    b = build_bundle(rich_analysis())
    bid, path = save_bundle(b, tmp_path)
    assert path.name == f"{bid}.json"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == bid
    assert save_bundle(b, tmp_path) == (bid, path)
    assert [p.name for p in tmp_path.iterdir()] == [path.name]  # no temp files left
    assert load_bundle(path) == b


def test_load_detects_tampering(tmp_path):
    bid, path = save_bundle(build_bundle(rich_analysis()), tmp_path)
    path.write_bytes(path.read_bytes().replace(b"TestFamily", b"BenignApp!"))
    with pytest.raises(BundleError, match="hash mismatch"):
        load_bundle(path)


def test_save_refuses_to_overwrite_a_mismatched_file(tmp_path):
    b = build_bundle(rich_analysis())
    bid = bundle_id(b)
    (tmp_path / f"{bid}.json").write_bytes(b"{}")
    with pytest.raises(BundleError, match="does not match"):
        save_bundle(b, tmp_path)
