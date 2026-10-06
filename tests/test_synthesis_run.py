import json

import pytest

from pipeline.llm_synthesis import manifest as mf
from pipeline.llm_synthesis.bundle import build_bundle, save_bundle
from pipeline.llm_synthesis.engines import EngineResult, get_engine
from pipeline.llm_synthesis.pricing import estimate_cost
from pipeline.llm_synthesis.prompt_builder import render
from pipeline.llm_synthesis.synthesizer import parse_model_json, run_synthesis
from tests.fixtures import good_v1, good_v2, rich_analysis

GOOD = good_v2()


class FakeEngine:
    id = "anthropic-api"

    def __init__(self, text=None, error=None, raw=True, stop="end_turn"):
        self._text, self._error, self._raw, self._stop = text, error, raw, stop

    def run(self, prompt):
        return EngineResult(
            engine_id=self.id, text=self._text, error=self._error,
            raw={"content": [{"type": "text", "text": self._text}]} if self._raw else None,
            model_requested="claude-sonnet-5-5", model_reported="claude-sonnet-5-5",
            params={"max_tokens": 16000}, defaults_assumed={"thinking": "adaptive"},
            usage={"input_tokens": 1000, "output_tokens": 5000},
            response_id="msg_1", stop_reason=self._stop, sdk="anthropic 0.86.0",
        )


@pytest.fixture
def setup(tmp_path):
    a = rich_analysis()
    b = build_bundle(a, analyst_notes="note")
    bid, bpath = save_bundle(b, tmp_path / "bundles")
    r = render(b)
    return a, r, bid, bpath, tmp_path / "runs"


def run(setup, engine, **kw):
    a, r, bid, bpath, runs = setup
    return run_synthesis(a, r, bid, bpath, engine, estimate_cost(r.prompt), runs_dir=runs, **kw)


def load_manifest(result, runs):
    return json.loads((runs / result["manifest"]["run_id"] / "manifest.json").read_text())


def test_success_writes_run_dir_manifest_and_raw(setup):
    runs = setup[4]
    res = run(setup, FakeEngine(json.dumps(GOOD)), analyst_notes="note")
    assert res["error"] is None and res["synthesis"]["ttp_mapping"]["confidence"] == "high"
    m = load_manifest(res, runs)
    assert set(mf.REQUIRED_KEYS) <= set(m)
    assert m["status"] == "ok" and m["mode"] == "prod"
    assert m["bundle"]["sha256"] == setup[2] == res["bundle_sha256"]
    assert m["template"] == {"id": "synthesis_v2", "sha256": setup[1].template_sha256}
    assert m["output_schema"]["id"] == "synthesis_output.v2" and m["output_schema"]["constrained_decoding"] is False
    assert m["validation"]["schema_valid"] is True and m["validation"]["errors"] == []
    assert m["prompt_sha256"] == setup[1].prompt_sha256
    assert m["usage"] == {"input_tokens": 1000, "output_tokens": 5000}
    assert m["cost"]["actual_usd"] == pytest.approx(1000 / 1e6 * 2 + 5000 / 1e6 * 10)
    assert m["analyst_notes_present"] is True and res["analyst_notes"] == "note"
    assert m["validation"]["parsed_json"] is True
    assert (runs / res["manifest"]["run_id"] / "raw_response.json").exists()
    assert res["manifest"]["run_id"].split("_")[1] == setup[2][:8]


def test_yara_fixup_still_applied(setup):
    res = run(setup, FakeEngine(json.dumps(GOOD)))
    rule = res["synthesis"]["yara_rule"]["rule"]
    assert '$a = "x"' in rule and "$junk" not in rule


def test_engine_error_records_failed_manifest(setup):
    res = run(setup, FakeEngine(text="partial", error="response truncated at max_tokens=16000", stop="max_tokens"))
    assert res["error"].startswith("response truncated") and res["synthesis"] is None
    m = load_manifest(res, setup[4])
    assert m["status"] == "error" and m["response"]["stop_reason"] == "max_tokens"


def test_unparseable_output_is_an_error(setup):
    res = run(setup, FakeEngine("I think this sample is benign."))
    assert "parse" in res["error"]
    assert load_manifest(res, setup[4])["validation"]["parsed_json"] is False


def test_dry_run_engine_manifest(setup):
    res = run(setup, get_engine("dry-run"))
    assert res["dry_run"] is True and res["error"] is None
    m = load_manifest(res, setup[4])
    assert m["engine"]["id"] == "dry-run" and m["usage"] is None and m["raw_response_path"] is None
    assert m["cost"]["actual_usd"] is None


def test_run_ids_unique_within_a_second(setup):
    ids = {mf.new_run_id("ab" * 32, "dry-run") for _ in range(50)}
    assert len(ids) == 50


@pytest.mark.parametrize("text", [
    json.dumps(GOOD),
    "```json\n" + json.dumps(GOOD) + "\n```",
    "```\n" + json.dumps(GOOD) + "\n```",
    "Here is the analysis:\n" + json.dumps(GOOD) + "\nDone.",
])
def test_parse_model_json_variants(text):
    assert parse_model_json(text) == GOOD


@pytest.mark.parametrize("text", ["", "no json here", "[1, 2]", "{broken"])
def test_parse_model_json_rejects(text):
    with pytest.raises(ValueError):
        parse_model_json(text)


def test_pipeline_commit_never_raises(tmp_path):
    info = mf.pipeline_commit(tmp_path)  # not a git repo
    assert info == {"commit": None, "dirty": None}
    (tmp_path / "DEPLOYED_COMMIT").write_text("abc123\n")
    assert mf.pipeline_commit(tmp_path)["commit"] == "abc123"


def test_build_manifest_requires_all_keys():
    with pytest.raises(ValueError, match="missing"):
        mf.build_manifest(run_id="x")


def test_schema_invalid_output_is_rejected_and_recorded(setup):
    bad = good_v2()
    del bad["iocs"]
    bad["verdict"]["classification"] = "probably bad"
    res = run(setup, FakeEngine(json.dumps(bad)))
    assert res["synthesis"] is None and "schema validation" in res["error"]
    m = load_manifest(res, setup[4])
    assert m["status"] == "error" and m["validation"]["parsed_json"] is True
    assert m["validation"]["schema_valid"] is False
    assert any("iocs" in e for e in m["validation"]["errors"])
    assert any("classification" in e for e in m["validation"]["errors"])
    assert res["validation_errors"] == m["validation"]["errors"]


def test_normalization_recorded(setup):
    out = good_v2()
    out["verdict"]["confidence"] = "High"
    out["ttp_mapping"]["techniques"][0]["id"] = " t1055 "
    res = run(setup, FakeEngine(json.dumps(out)))
    assert res["error"] is None
    assert res["synthesis"]["verdict"]["confidence"] == "high"
    assert res["synthesis"]["ttp_mapping"]["techniques"][0]["id"] == "T1055"
    m = load_manifest(res, setup[4])
    assert "verdict.confidence" in m["validation"]["normalized"]


def test_v1_template_validates_against_v1_schema(tmp_path):
    a = rich_analysis()
    b = build_bundle(a)
    bid, bpath = save_bundle(b, tmp_path / "bundles")
    r = render(b, "synthesis_v1")
    res = run_synthesis(a, r, bid, bpath, FakeEngine(json.dumps(good_v1())), estimate_cost(r.prompt),
                        runs_dir=tmp_path / "runs")
    assert res["error"] is None
    m = json.loads((tmp_path / "runs" / res["manifest"]["run_id"] / "manifest.json").read_text())
    assert m["output_schema"]["id"] == "synthesis_output.v1"
