import copy
import hashlib
import json

import pytest

from pipeline.llm_synthesis import prompt_builder
from pipeline.llm_synthesis.bundle import build_bundle
from pipeline.llm_synthesis.engines.dry_run import DRY_RUN_SYNTHESIS
from pipeline.llm_synthesis.output_validation import (
    SCHEMA_DIR,
    SchemaError,
    load_schema,
    schema_for_template,
    validate_output,
)
from pipeline.llm_synthesis.prompt_builder import load_template, render
from tests.fixtures import good_v1, good_v2, rich_analysis

V2 = "synthesis_output.v2"
V1 = "synthesis_output.v1"


def errors_for(doc, schema=V2):
    out, rep = validate_output(doc, schema)
    return out, rep["errors"]


def test_valid_v2_passes():
    out, rep = validate_output(good_v2(), V2)
    assert rep["valid"] and out == good_v2() and rep["normalized"] == []


@pytest.mark.parametrize("key", ["verdict", "ttp_mapping", "yara_rule", "sigma_rule",
                                 "technical_report", "iocs", "manipulation_observed"])
def test_each_missing_top_level_field_fails(key):
    d = good_v2()
    del d[key]
    out, errs = errors_for(d)
    assert out is None and any(key in e for e in errs)


@pytest.mark.parametrize("path", [
    ("verdict", "family"), ("verdict", "classification"), ("iocs", "domains"),
    ("manipulation_observed", "detected"), ("manipulation_observed", "evidence"),
    ("sigma_rule", "log_sources"), ("technical_report", "key_indicators"),
])
def test_missing_nested_fields_fail(path):
    d = good_v2()
    del d[path[0]][path[1]]
    assert errors_for(d)[0] is None


@pytest.mark.parametrize("mutate", [
    lambda d: d["verdict"].__setitem__("classification", "likely malicious"),
    lambda d: d["verdict"].__setitem__("confidence", "n/a"),
    lambda d: d["yara_rule"].__setitem__("confidence", "very high"),
    lambda d: d["manipulation_observed"].__setitem__("detected", "true"),
    lambda d: d["iocs"]["ips"].append({"ip": "1.2.3.4"}),
    lambda d: d["verdict"].__setitem__("family", 7),
])
def test_bad_values_fail(mutate):
    d = good_v2()
    mutate(d)
    assert errors_for(d)[0] is None


@pytest.mark.parametrize("tid", ["T10", "T1055.1", "Process Injection", "TA0005", "T1055.0011", ""])
def test_bad_technique_ids_fail(tid):
    d = good_v2()
    d["ttp_mapping"]["techniques"][0]["id"] = tid
    assert errors_for(d)[0] is None


def test_extra_keys_rejected_at_top_level_and_closed_objects():
    for mutate in (lambda d: d.__setitem__("notes", "x"),
                   lambda d: d["verdict"].__setitem__("score", 9),
                   lambda d: d["iocs"].__setitem__("emails", [])):
        d = good_v2()
        mutate(d)
        assert errors_for(d)[0] is None


def test_case_and_whitespace_normalized_and_reported():
    d = good_v2()
    d["verdict"]["classification"] = "Malicious "
    d["verdict"]["confidence"] = "HIGH"
    d["sigma_rule"]["confidence"] = "Low"
    d["ttp_mapping"]["techniques"][1]["id"] = "t1027.002"
    out, rep = validate_output(d, V2)
    assert rep["valid"]
    assert out["verdict"] == {"classification": "malicious", "family": "TestFamily", "confidence": "high"}
    assert out["ttp_mapping"]["techniques"][1]["id"] == "T1027.002"
    assert set(rep["normalized"]) == {"verdict.classification", "verdict.confidence",
                                      "sigma_rule.confidence", "ttp_mapping.techniques[1].id"}
    assert d["verdict"]["confidence"] == "HIGH"  # input untouched


def test_family_may_be_null():
    d = good_v2()
    d["verdict"]["family"] = None
    assert validate_output(d, V2)[1]["valid"]


def test_non_object_output():
    out, rep = validate_output(["not", "an", "object"], V2)
    assert out is None and "expected an object" in rep["errors"][0]


def test_v1_schema_is_the_legacy_shape():
    assert validate_output(good_v1(), V1)[1]["valid"]
    assert validate_output(good_v2(), V1)[1]["valid"]   # extra top-level keys allowed in v1
    assert not validate_output(good_v1(), V2)[1]["valid"]


def test_dry_run_placeholder_validates_under_both():
    for schema in (V1, V2):
        assert validate_output(copy.deepcopy(DRY_RUN_SYNTHESIS), schema)[1]["valid"]


def test_error_list_is_capped():
    d = good_v2()
    d["ttp_mapping"]["techniques"] = [{"id": "bad"}] * 100
    _, rep = validate_output(d, V2)
    assert len(rep["errors"]) == 51 and rep["errors"][-1].startswith("...")


def test_schema_hash_and_mapping():
    schema, sha = load_schema(V2)
    assert sha == hashlib.sha256((SCHEMA_DIR / f"{V2}.json").read_bytes()).hexdigest()
    assert schema["$id"] == V2
    assert schema_for_template("synthesis_v1") == V1 and schema_for_template("synthesis_v2") == V2
    with pytest.raises(SchemaError):
        schema_for_template("synthesis_v9")
    with pytest.raises(SchemaError):
        load_schema("synthesis_output.v9")


# ── v2 template ─────────────────────────────────────────────────────────────

def test_v2_is_the_default_template():
    assert prompt_builder.DEFAULT_TEMPLATE == "synthesis_v2"


def test_v2_input_section_identical_to_v1():
    b = build_bundle(rich_analysis(), analyst_notes="note")
    p1 = render(b, "synthesis_v1").prompt
    p2 = render(b, "synthesis_v2").prompt
    head1, _, tail1 = p1.partition("\n---\n\nProduce the following output")
    head2, _, tail2 = p2.partition("\n---\n\nProduce the following output")
    assert head1 == head2 and tail1 != tail2
    assert p1.endswith("## Analyst Notes\nnote") and p2.endswith("## Analyst Notes\nnote")


def test_v2_asks_for_every_schema_field():
    text, _ = load_template("synthesis_v2")
    schema, _ = load_schema(V2)
    for key in schema["required"]:
        assert f'"{key}"' in text
    for sub in ("classification", "family", "domains", "hashes", "detected", "evidence"):
        assert f'"{sub}"' in text
    assert "manipulation_observed.detected to true" in text


def test_v2_does_not_prime_the_manipulation_flag():
    text, _ = load_template("synthesis_v2")
    assert '"detected": true|false' in text


def test_v2_has_no_stray_placeholders():
    import re
    text, _ = load_template("synthesis_v2")
    names = set(re.findall(r"\$([_a-z][_a-z0-9]*)", text))
    assert names == set(prompt_builder._fields_v1(build_bundle({})))


def test_schemas_are_valid_json_schema():
    from jsonschema import Draft202012Validator
    for p in SCHEMA_DIR.glob("*.json"):
        Draft202012Validator.check_schema(json.loads(p.read_text()))
