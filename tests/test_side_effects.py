"""D2.5: the eval-mode guard on every production writer, the report/validate
split, and dry runs leaving the DB and quarantine alone."""

import importlib
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

from pipeline.utils import run_context
from pipeline.utils.run_context import SideEffectBlocked
from tests.fixtures import good_v2

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def eval_mode(monkeypatch):
    monkeypatch.setenv(run_context.ENV_VAR, "unit")
    yield "unit"


@pytest.fixture
def stub_heavy(monkeypatch):
    """Stand-ins for stix2 and pyvis so their modules import without the packages."""
    stix2 = types.ModuleType("stix2")
    for name in ("Bundle", "Malware", "Indicator", "AttackPattern", "Relationship",
                 "Report", "Identity", "ExternalReference"):
        setattr(stix2, name, type(name, (), {"__init__": lambda self, *a, **k: None}))
    exc = types.ModuleType("stix2.exceptions")
    exc.InvalidValueError = type("InvalidValueError", (Exception,), {})
    pyvis = types.ModuleType("pyvis")
    net = types.ModuleType("pyvis.network")
    net.Network = type("Network", (), {"__init__": lambda self, *a, **k: None})
    for name, mod in (("stix2", stix2), ("stix2.exceptions", exc), ("pyvis", pyvis), ("pyvis.network", net)):
        monkeypatch.setitem(sys.modules, name, mod)


# ── run_context ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("label", ["bench-01", "a", "run_2026.10.06"])
def test_valid_labels(label):
    assert run_context.validate_label(label) == label


@pytest.mark.parametrize("label", ["", "../x", "a/b", "-x", "x" * 65, "a b", "a..b"])
def test_invalid_labels(label):
    with pytest.raises(ValueError):
        run_context.validate_label(label)


def test_guard_off_in_prod(monkeypatch):
    monkeypatch.delenv(run_context.ENV_VAR, raising=False)
    run_context.require_side_effects("anything")  # no raise


def test_guard_on_in_eval(eval_mode):
    with pytest.raises(SideEffectBlocked, match="unit"):
        run_context.require_side_effects("x")
    assert run_context.eval_root(REPO) == REPO / "output" / "eval" / "unit"


def test_eval_mode_inherited_by_child_processes(eval_mode):
    out = subprocess.run([sys.executable, "-c",
                          "import sys; sys.path.insert(0, sys.argv[1]);"
                          "from pipeline.utils.run_context import is_eval; print(is_eval())", str(REPO)],
                         capture_output=True, text=True)
    assert out.stdout.strip() == "True"


# ── every production writer refuses in eval mode ────────────────────────────

def _calls():
    from pipeline.delta_analysis import delta
    from pipeline.reporting import publish, report_builder, rule_extractor
    from pipeline.rule_validation import validate
    from pipeline.llm_synthesis import synthesizer
    from pipeline.rag import indexer
    from pipeline.utils import db
    from pipeline.export import stix_export
    from pipeline.delta_analysis import threat_graph
    draft = importlib.import_module("scripts.draft_post")
    syn = {"sample": {"sha256": "a" * 64}, "synthesis": good_v2()}
    return {
        "db.update_status": lambda: db.update_status("a" * 64, "REPORTED"),
        "db.update_triage_score": lambda: db.update_triage_score("a" * 64, 1, False),
        "report_builder.save_report": lambda: report_builder.save_report("x", Path("/nonexistent/x.md")),
        "rule_extractor.extract_yara": lambda: rule_extractor.extract_yara(syn),
        "rule_extractor.extract_sigma": lambda: rule_extractor.extract_sigma(syn),
        "synthesizer.save_synthesis": lambda: synthesizer.save_synthesis(syn),
        "validate.save_validation_report": lambda: validate.save_validation_report({"sha256": "a" * 64}),
        "indexer.index_corpus": lambda: indexer.index_corpus(),
        "delta.generate_delta": lambda: delta.generate_delta("a" * 64),
        "stix_export.export_stix": lambda: stix_export.export_stix("a" * 64),
        "threat_graph.render_graph": lambda: threat_graph.render_graph({"nodes": [], "edges": []}),
        "draft_post.draft_post": lambda: draft.draft_post("a" * 64),
        "publish.publish_after_approval": lambda: publish.publish_after_approval("a" * 64),
    }


WRITERS = ["db.update_status", "db.update_triage_score", "report_builder.save_report",
           "rule_extractor.extract_yara", "rule_extractor.extract_sigma", "synthesizer.save_synthesis",
           "validate.save_validation_report", "indexer.index_corpus", "delta.generate_delta",
           "stix_export.export_stix", "threat_graph.render_graph", "draft_post.draft_post",
           "publish.publish_after_approval"]


@pytest.mark.parametrize("name", WRITERS)
def test_writer_blocked_in_eval(name, eval_mode, stub_heavy):
    with pytest.raises(SideEffectBlocked):
        _calls()[name]()


def test_importing_db_touches_nothing():
    """Importing pipeline.utils.db (as report.py, analyze.py and the dashboard do)
    must not create or modify pipeline.db. Holds on pipeline, where a real DB exists."""
    db_file = REPO / "pipeline.db"

    def state():
        return (db_file.stat().st_mtime_ns, db_file.stat().st_size) if db_file.exists() else None

    before = state()
    out = subprocess.run([sys.executable, "-c",
                          "import sys; sys.path.insert(0, sys.argv[1]); import pipeline.utils.db", str(REPO)],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert state() == before


def test_db_schema_created_on_first_write(tmp_path, monkeypatch):
    monkeypatch.delenv(run_context.ENV_VAR, raising=False)
    from pipeline.utils import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "pipeline.db")
    monkeypatch.setattr(db, "_initialized", False)
    db.update_status("b" * 64, "ACQUIRED", "Fam")
    assert db.get_samples_by_status("ACQUIRED") == ["b" * 64]


# ── report.py: no publish steps; dry runs leave DB and quarantine alone ─────

@pytest.fixture
def report_env(tmp_path, monkeypatch):
    monkeypatch.delenv(run_context.ENV_VAR, raising=False)
    from pipeline.reporting import report, rule_extractor
    calls = []
    monkeypatch.setattr(report, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "output" / "reports")
    monkeypatch.setattr(report, "update_status", lambda sha, st: calls.append((sha, st)))
    monkeypatch.setattr(rule_extractor, "YARA_DIR", tmp_path / "rules" / "yara")
    monkeypatch.setattr(rule_extractor, "SIGMA_DIR", tmp_path / "rules" / "sigma")
    q = tmp_path / "samples" / "quarantine"
    q.mkdir(parents=True)
    return report, calls, tmp_path, q


def write_synthesis(root, sha, dry_run):
    d = root / "output" / "reports"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{sha}.synthesis.json").write_text(json.dumps(
        {"sample": {"sha256": sha, "malware_family": "Fam"}, "synthesis": good_v2(), "dry_run": dry_run}))


def test_report_dry_run_leaves_db_and_quarantine(report_env):
    report, calls, root, q = report_env
    sha = "c" * 64
    (q / f"{sha}.zip").write_bytes(b"zip")
    write_synthesis(root, sha, dry_run=True)
    report.generate_reports(sha)
    assert calls == [] and (q / f"{sha}.zip").exists()


def test_report_real_run_marks_reported_and_cleans_up(report_env):
    report, calls, root, q = report_env
    sha = "d" * 64
    (q / f"{sha}.zip").write_bytes(b"zip")
    (q / f"{sha}.meta.json").write_text("{}")
    write_synthesis(root, sha, dry_run=False)
    report.generate_reports(sha)
    assert calls == [(sha, "REPORTED")] and not (q / f"{sha}.zip").exists()
    assert not (q / f"{sha}.meta.json").exists()


def test_report_module_no_longer_imports_publish_steps():
    src = (REPO / "pipeline" / "reporting" / "report.py").read_text()
    for name in ("index_corpus", "generate_delta", "export_stix"):
        assert name not in src


# ── validate.py: publish only on approval ───────────────────────────────────

@pytest.mark.parametrize("answer,published", [("y", True), ("n", False), ("s", False)])
def test_publish_only_after_approval(answer, published, tmp_path, monkeypatch):
    monkeypatch.delenv(run_context.ENV_VAR, raising=False)
    from pipeline.reporting import publish
    from pipeline.rule_validation import validate
    seen = []
    monkeypatch.setattr(publish, "publish_after_approval", lambda sha: seen.append(sha) or True)
    monkeypatch.setattr(validate, "YARA_DIR", tmp_path / "y")
    monkeypatch.setattr(validate, "SIGMA_DIR", tmp_path / "s")
    monkeypatch.setattr(validate, "VALIDATION_DIR", tmp_path / "v")
    monkeypatch.setattr("builtins.input", lambda *_: answer)
    rep = validate.run_validation("e" * 64)
    assert (seen == ["e" * 64]) is published and rep["published"] is published
    assert json.loads((tmp_path / "v" / f"{'e' * 64}.validation.json").read_text())["published"] is published


def test_host_pipeline_has_no_separate_delta_stage():
    sh = (REPO / "scripts" / "run_host_pipeline.sh").read_text()
    assert "delta.py" not in sh and "[3/3]" in sh and "[4/4]" not in sh
