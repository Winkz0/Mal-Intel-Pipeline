"""D2.6, pipeline side: export, import checks, and the full loop end to end
(synthesize --engine desktop -> pull -> MCP server over stdio -> push ->
queue_import -> prompt_compare) in a throwaway repo copy."""

import json
import shutil
import subprocess
import sys

import pytest

from pipeline.llm_synthesis import desktop_queue
from pipeline.utils import run_context
from tests.fixtures import good_v2, rich_analysis
from tests.vivo_helpers import REPO, VIVO, fake_tools, make_queue_request, write_config


@pytest.fixture
def q(tmp_path):
    return tmp_path / "queue", tmp_path / "bundles", tmp_path / "runs"


def returned(qdir, sha, synthesis=None, **override):
    doc = {"submission_version": 1, "bundle_sha256": sha, "schema_id": "synthesis_output.v2",
           "submitted_at": "2026-10-06T00:00:00+00:00", "synthesis": synthesis or good_v2(), **override}
    p = qdir / "returned" / f"{sha}.synthesis.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc))
    return p


def run_import(q, saved=None):
    qdir, bdir, runs = q
    return desktop_queue.import_returned(qdir, bdir, "claude-opus-5-5 (Desktop)", runs_dir=runs,
                                         mode="prod", save=(saved.append if saved is not None else None))


def test_export_request_contents(q):
    qdir, bdir, _ = q
    sha, path = make_queue_request(qdir, bdir, rich_analysis(), notes="n")
    req = json.loads(path.read_text())
    assert req["bundle_sha256"] == sha and req["template"]["id"] == "synthesis_v2"
    assert req["output_schema"]["id"] == "synthesis_output.v2" and req["analyst_notes_present"] is True
    assert req["sample"]["sha256"] == "a" * 64 and "Ignore previous instructions" in req["prompt"]
    again, created = desktop_queue.export_request(qdir, sha, None, {}, False, "prod")
    assert again == path and created is False
    assert len((qdir / "exports.jsonl").read_text().splitlines()) == 1


def test_import_happy_path(q):
    qdir, bdir, runs = q
    sha, _ = make_queue_request(qdir, bdir, rich_analysis())
    returned(qdir, sha)
    saved = []
    (o,) = run_import(q, saved)
    assert o["status"] == "imported" and o["error"] is None
    assert len(saved) == 1 and saved[0]["engine"] == "desktop-mcp"
    run = next(runs.iterdir())
    m = json.loads((run / "manifest.json").read_text())
    assert m["engine"]["id"] == "desktop-mcp" and m["model"]["reported"] == "claude-opus-5-5 (Desktop)"
    assert m["model"]["requested"] is None and m["usage"] is None and m["cost"]["actual_usd"] is None
    assert m["validation"]["schema_valid"] and m["bundle"]["sha256"] == sha
    assert "Desktop" in m["defaults_assumed"]["engine"]
    assert json.loads((run / "raw_response.json").read_text())["submitted_at"]
    assert (qdir / "imported" / f"{sha}.request.json").exists()
    assert not (qdir / "pending" / f"{sha}.request.json").exists()
    assert not list((qdir / "returned").iterdir())


def test_schema_invalid_answer_keeps_request_pending(q):
    qdir, bdir, runs = q
    sha, _ = make_queue_request(qdir, bdir, rich_analysis())
    bad = good_v2()
    bad["verdict"]["classification"] = "likely"
    returned(qdir, sha, synthesis=bad)
    saved = []
    (o,) = run_import(q, saved)
    assert o["status"] == "invalid" and "schema validation" in o["error"] and saved == []
    assert (qdir / "pending" / f"{sha}.request.json").exists()
    assert len(list((qdir / "rejected").iterdir())) == 1
    m = json.loads((next(runs.iterdir()) / "manifest.json").read_text())
    assert m["status"] == "error" and m["engine"]["id"] == "desktop-mcp"


@pytest.mark.parametrize("case,needle", [
    ("unknown", "no pending request"),
    ("name_mismatch", "does not match its name"),
    ("no_synthesis", "no synthesis object"),
    ("bundle_altered", "stored bundle missing or altered"),
    ("bundle_missing", "stored bundle missing or altered"),
    ("bad_name", "file name"),
    ("too_big", "larger than"),
    ("not_json", "not JSON"),
])
def test_import_rejections(q, case, needle):
    qdir, bdir, runs = q
    sha, _ = make_queue_request(qdir, bdir, rich_analysis())
    if case == "unknown":
        returned(qdir, "e" * 64)
    elif case == "name_mismatch":
        p = returned(qdir, sha)
        p.write_text(json.dumps({"bundle_sha256": "e" * 64, "synthesis": good_v2()}))
    elif case == "no_synthesis":
        returned(qdir, sha).write_text(json.dumps({"bundle_sha256": sha}))
    elif case == "bundle_altered":
        returned(qdir, sha)
        (bdir / f"{sha}.json").write_bytes(b"{}")
    elif case == "bundle_missing":
        returned(qdir, sha)
        (bdir / f"{sha}.json").unlink()
    elif case == "bad_name":
        (qdir / "returned").mkdir(parents=True, exist_ok=True)
        (qdir / "returned" / "evil.json").write_text("{}")
    elif case == "too_big":
        returned(qdir, sha, padding="x" * (desktop_queue.MAX_RETURNED_BYTES + 1))
    elif case == "not_json":
        returned(qdir, sha).write_text("{oops")
    saved = []
    (o,) = run_import(q, saved)
    assert o["status"] == "rejected" and needle in o["error"], o
    assert saved == [] and not runs.exists()


def test_prompt_hash_mismatch_is_rejected(q):
    qdir, bdir, _ = q
    sha, path = make_queue_request(qdir, bdir, rich_analysis())
    req = json.loads(path.read_text())
    req["prompt_sha256"] = "0" * 64
    path.write_text(json.dumps(req))
    returned(qdir, sha)
    (o,) = run_import(q)
    assert o["status"] == "rejected" and "no longer renders" in o["error"]


def test_template_change_since_export_is_rejected(q):
    qdir, bdir, _ = q
    sha, path = make_queue_request(qdir, bdir, rich_analysis())
    req = json.loads(path.read_text())
    req["template"]["sha256"] = "0" * 64
    path.write_text(json.dumps(req))
    returned(qdir, sha)
    (o,) = run_import(q)
    assert o["status"] == "rejected" and "template changed" in o["error"]


# ── end to end ──────────────────────────────────────────────────────────────

def run(cmd, cwd, **kw):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120, **kw)
    assert p.returncode == 0, f"{cmd}\n{p.stdout}\n{p.stderr}"
    return p.stdout


def test_full_desktop_loop_end_to_end(tmp_path, monkeypatch):
    monkeypatch.delenv(run_context.ENV_VAR, raising=False)
    remote_home = tmp_path / "remote"
    repo = remote_home / "repo"
    for d in ("pipeline", "scripts"):
        shutil.copytree(REPO / d, repo / d, ignore=shutil.ignore_patterns("__pycache__"))
    (repo / "config").mkdir()
    sha = "a" * 64
    (repo / "output" / "analysis").mkdir(parents=True)
    (repo / "output" / "analysis" / f"{sha}.analysis.json").write_text(json.dumps(rich_analysis()))
    vivo_q = tmp_path / "vivo-queue"
    write_config(vivo_q, fake_tools(tmp_path, monkeypatch, remote_home))
    py = sys.executable
    synth = str(repo / "pipeline" / "llm_synthesis" / "synthesize.py")

    # 1. pipeline: export for Desktop (eval, so nothing touches production state)
    out = run([py, synth, sha, "--engine", "desktop", "--eval", "e2e", "--skip-checkpoint"], repo)
    assert "Queued for Claude Desktop" in out
    pending = list((repo / "output" / "eval" / "e2e" / "queue" / "pending").glob("*.request.json"))
    assert len(pending) == 1
    bundle_sha = pending[0].name[:64]

    # 2. Vivo: pull
    out = run([py, str(VIVO / "queue_transfer.py"), "pull", "--eval", "e2e", "--queue", str(vivo_q)], tmp_path)
    assert "1 new request" in out

    # 3. Vivo: Claude Desktop talks to the MCP server over stdio
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_bundle", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "submit_synthesis", "arguments": {
            "bundle_sha256": bundle_sha, "synthesis_json": json.dumps(good_v2())}}},
    ]
    p = subprocess.run([py, "-I", str(VIVO / "synthesis_queue_mcp" / "server.py"), "--queue", str(vivo_q),
                        "--repo", str(REPO)], input="".join(json.dumps(m) + "\n" for m in msgs),
                       capture_output=True, text=True, timeout=60)
    replies = [json.loads(ln) for ln in p.stdout.splitlines()]
    assert replies[1]["result"]["isError"] is False and bundle_sha in replies[1]["result"]["content"][0]["text"]
    assert replies[2]["result"]["isError"] is False, replies[2]

    # 4. Vivo: push
    out = run([py, str(VIVO / "queue_transfer.py"), "push", "--queue", str(vivo_q)], tmp_path)
    assert "1 answer(s) delivered" in out

    # 5. pipeline: import
    out = run([py, str(repo / "scripts" / "queue_import.py"), "--model", "claude-opus-5-5", "--eval", "e2e"], repo)
    assert "1 imported, 0 rejected" in out
    runs = list((repo / "output" / "eval" / "e2e" / "runs").iterdir())
    assert len(runs) == 1
    m = json.loads((runs[0] / "manifest.json").read_text())
    assert m["engine"]["id"] == "desktop-mcp" and m["mode"] == "eval" and m["validation"]["schema_valid"]
    assert not (repo / "pipeline.db").exists() and not (repo / "output" / "reports").exists()

    # 6. same bundle through another engine, then score one against the other
    run([py, synth, sha, "--dry-run", "--eval", "e2e", "--skip-checkpoint"], repo)
    dry = [r for r in (repo / "output" / "eval" / "e2e" / "runs").iterdir() if "dry-run" in r.name][0]
    out = run([py, str(repo / "scripts" / "prompt_compare.py"), str(dry), str(runs[0])], repo)
    assert "same bundle: yes" in out and "engine=desktop-mcp" in out
