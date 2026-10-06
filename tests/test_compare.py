import json
import subprocess
import sys

import pytest

from pipeline.eval.compare import (
    CompareInputError,
    aggregate,
    compare,
    load_synthesis,
    refang,
    set_metrics,
)
from tests.fixtures import good_v1, good_v2

REPO = __import__("pathlib").Path(__file__).resolve().parents[1]


def test_identical_scores_perfect():
    s = compare(good_v2(), good_v2())
    assert s["verdict"]["classification"]["match"] and s["verdict"]["family"]["match"]
    assert s["verdict"]["confidence"]["delta"] == 0
    assert s["attack"]["exact"]["jaccard"] == 1.0 and s["attack"]["exact"]["precision"] == 1.0
    assert s["iocs"]["ips"]["jaccard"] == 1.0 and s["iocs"]["urls"]["empty"] is True
    assert s["manipulation"]["match"] is True
    assert s["rules"]["yara_rule"] == {"ref": True, "cand": True}


def test_disjoint_scores_zero():
    c = good_v2()
    c["verdict"] = {"classification": "benign", "family": "Other", "confidence": "low"}
    c["ttp_mapping"]["techniques"] = [{"id": "T1003", "name": "", "tactic": "", "evidence": ""}]
    c["iocs"]["ips"] = ["203.0.113.1"]
    c["manipulation_observed"] = {"detected": True, "evidence": ["ignore previous"]}
    s = compare(good_v2(), c)
    assert s["verdict"]["classification"]["match"] is False and s["verdict"]["family"]["match"] is False
    assert s["verdict"]["confidence"]["delta"] == -2
    assert s["attack"]["exact"]["jaccard"] == 0.0 and s["attack"]["parent"]["jaccard"] == 0.0
    assert s["iocs"]["ips"]["jaccard"] == 0.0
    assert s["manipulation"] == {"ref": False, "cand": True, "match": False, "cand_evidence_count": 1}


def test_parent_technique_matching():
    r, c = good_v2(), good_v2()
    r["ttp_mapping"]["techniques"] = [{"id": "T1055.012", "name": "", "tactic": "", "evidence": ""}]
    c["ttp_mapping"]["techniques"] = [{"id": "T1055", "name": "", "tactic": "", "evidence": ""}]
    s = compare(r, c)["attack"]
    assert s["exact"]["jaccard"] == 0.0 and s["parent"]["jaccard"] == 1.0
    assert s["exact"]["missed"] == ["T1055.012"] and s["exact"]["extra"] == ["T1055"]


def test_precision_recall_direction():
    r, c = good_v2(), good_v2()
    c["ttp_mapping"]["techniques"] = c["ttp_mapping"]["techniques"][:1]  # found 1 of 2
    m = compare(r, c)["attack"]["exact"]
    assert m["precision"] == 1.0 and m["recall"] == 0.5 and m["jaccard"] == 0.5


@pytest.mark.parametrize("ref,cand", [
    ("hxxp://Example[.]Test/Path/", "http://example.test/Path"),
    ("hxxps://bad[.]example(.)test", "https://bad.example.test"),
])
def test_url_normalization(ref, cand):
    r, c = good_v2(), good_v2()
    r["iocs"]["urls"], c["iocs"]["urls"] = [ref], [cand]
    assert compare(r, c)["iocs"]["urls"]["jaccard"] == 1.0


def test_url_path_case_is_significant():
    r, c = good_v2(), good_v2()
    r["iocs"]["urls"], c["iocs"]["urls"] = ["http://x.test/A"], ["http://x.test/a"]
    assert compare(r, c)["iocs"]["urls"]["jaccard"] == 0.0


def test_other_ioc_normalization():
    r, c = good_v2(), good_v2()
    r["iocs"].update(domains=["EVIL[.]Example."], hashes=["ABCDEF"], ips=["198.51.100[.]7"],
                     commands=["wget  http://x  -O a"])
    c["iocs"].update(domains=["evil.example"], hashes=["abcdef"], ips=["198.51.100.7"],
                     commands=["wget http://x -O a"])
    i = compare(r, c)["iocs"]
    assert all(i[k]["jaccard"] == 1.0 for k in ("domains", "hashes", "ips", "commands"))
    assert i["all"]["jaccard"] == 1.0


def test_empty_set_convention():
    assert set_metrics(set(), set()) == {"ref": 0, "cand": 0, "tp": 0, "precision": None,
                                         "recall": None, "jaccard": 1.0, "empty": True}
    m = set_metrics(set(), {"a"})
    assert m["recall"] is None and m["precision"] == 0.0 and m["jaccard"] == 0.0
    m = set_metrics({"a"}, set())
    assert m["precision"] is None and m["recall"] == 0.0
    assert set_metrics(None, {"a"}) is None


def test_v1_outputs_score_none_for_new_fields():
    s = compare(good_v1(), good_v2())
    assert s["verdict"] is None and s["iocs"] is None and s["manipulation"] is None
    assert s["attack"]["exact"]["jaccard"] == 1.0


def test_dry_run_rules_not_present():
    c = good_v2()
    c["yara_rule"]["rule"] = "[DRY RUN]"
    assert compare(good_v2(), c)["rules"]["yara_rule"] == {"ref": True, "cand": False}


def test_invalid_technique_ids_ignored():
    c = good_v2()
    c["ttp_mapping"]["techniques"].append({"id": "Process Injection"})
    assert compare(good_v2(), c)["attack"]["exact"]["jaccard"] == 1.0


def test_refang():
    assert refang("hxxp://a[.]b[:]80") == "http://a.b:80"


def test_aggregate_skips_none_and_counts_empty():
    a = compare(good_v2(), good_v2())
    b = compare(good_v1(), good_v2())  # verdict None
    agg = aggregate([a, b])
    assert agg["pairs"] == 2
    assert agg["verdict_classification_match"] == {"rate": 1.0, "n": 1}
    assert agg["attack_exact_jaccard"] == {"mean": 1.0, "n": 2}
    assert agg["ioc_urls_both_empty"] == 1


# ── loading ─────────────────────────────────────────────────────────────────

def write_run(d, syn, bundle="b" * 64, status="ok", with_synthesis=True):
    d.mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps({
        "run_id": d.name, "status": status, "engine": {"id": "anthropic-api"},
        "model": {"requested": "claude-sonnet-5-5", "reported": "claude-sonnet-5-5"},
        "bundle": {"sha256": bundle}, "template": {"id": "synthesis_v2"}}))
    if with_synthesis:
        (d / "synthesis.json").write_text(json.dumps({"synthesis": syn, "bundle_sha256": bundle}))
    return d


def test_load_from_run_dir_result_file_and_bare(tmp_path):
    run = write_run(tmp_path / "run1", good_v2())
    syn, meta = load_synthesis(run)
    assert syn == good_v2() and meta["engine"] == "anthropic-api" and meta["bundle_sha256"] == "b" * 64
    (tmp_path / "r.json").write_text(json.dumps({"synthesis": good_v2(), "model": "m"}))
    assert load_synthesis(tmp_path / "r.json")[1]["model"] == "m"
    (tmp_path / "bare.json").write_text(json.dumps(good_v2()))
    assert load_synthesis(tmp_path / "bare.json")[0] == good_v2()


def test_load_errors(tmp_path):
    failed = write_run(tmp_path / "failed", None, status="error", with_synthesis=False)
    with pytest.raises(CompareInputError, match="status: error"):
        load_synthesis(failed)
    (tmp_path / "x.json").write_text("[1]")
    with pytest.raises(CompareInputError):
        load_synthesis(tmp_path / "x.json")


def run_cli(*args):
    return subprocess.run([sys.executable, str(REPO / "scripts" / "prompt_compare.py"), *map(str, args)],
                          capture_output=True, text=True, cwd=REPO)


def test_cli_two_runs_same_bundle(tmp_path):
    a = write_run(tmp_path / "api", good_v2())
    c = good_v2()
    c["ttp_mapping"]["techniques"] = c["ttp_mapping"]["techniques"][:1]
    b = write_run(tmp_path / "desk", c)
    p = run_cli(a, b)
    assert p.returncode == 0, p.stderr
    assert "same bundle: yes" in p.stdout and "missed T1027.002" in p.stdout
    j = json.loads(run_cli(a, b, "--json").stdout)
    assert j["pairs"][0]["scores"]["attack"]["exact"]["recall"] == 0.5 and j["aggregate"] is None


def test_cli_pairs_and_failure_exit(tmp_path):
    a = write_run(tmp_path / "a", good_v2())
    bad = write_run(tmp_path / "bad", None, status="error", with_synthesis=False)
    pairs = tmp_path / "pairs.json"
    pairs.write_text(json.dumps([{"ref": str(a), "cand": str(a), "label": "self"},
                                 {"ref": str(a), "cand": str(bad), "label": "broken"}]))
    p = run_cli("--pairs", pairs)
    assert p.returncode == 1 and "== aggregate" in p.stdout and "status: error" in p.stdout
