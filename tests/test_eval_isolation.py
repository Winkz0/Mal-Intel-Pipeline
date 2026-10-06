"""D2.5 exit check, end to end: an eval-mode synthesis in a throwaway copy of the
repo, seeded with production state, leaves every file outside output/eval/
byte-identical, and never imports pipeline.utils.db."""

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from tests.fixtures import rich_analysis

REPO = Path(__file__).resolve().parents[1]
SHA = "a" * 64
SHA2 = "f" * 64

BLOCK_DB = """
import runpy, sys
class Block:
    def find_spec(self, name, path=None, target=None):
        if name == "pipeline.utils.db":
            raise ImportError("pipeline.utils.db imported on the eval path")
        return None
sys.meta_path.insert(0, Block())
script = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(script, run_name="__main__")
"""


def snapshot(root: Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if rel.startswith("output/eval") or "__pycache__" in rel:
            continue
        out[rel] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "<dir>"
    return out


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    for d in ("pipeline", "scripts"):
        shutil.copytree(REPO / d, r / d, ignore=shutil.ignore_patterns("__pycache__"))
    (r / "config").mkdir()
    # production state the eval run must not touch
    con = sqlite3.connect(r / "pipeline.db")
    con.execute("CREATE TABLE samples (sha256 TEXT PRIMARY KEY, status TEXT)")
    con.execute("INSERT INTO samples VALUES (?, 'REPORTED')", (SHA,))
    con.commit()
    con.close()
    seeds = {
        "data/chromadb/chroma.sqlite3": "index",
        f"output/reports/{SHA}.synthesis.json": "{}",
        f"output/rules/yara/{SHA}.yar": "rule r { condition: true }",
        f"output/rules/sigma/{SHA}.yml": "title: t",
        f"output/stix/{SHA}.stix.json": "{}",
        "output/graphs/threat_graph.html": "<html></html>",
        "docs/_posts/2026-01-01-post.md": "post",
        f"output/bundles/{'0' * 64}.json": "{}",
        "output/runs/old/manifest.json": "{}",
        f"samples/quarantine/{SHA}.zip": "zip",
        f"output/analysis/{SHA}.analysis.json": json.dumps(rich_analysis()),
    }
    for rel, content in seeds.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(content)
    return r


def synth(repo: Path, *args, block_db=True):
    script = str(repo / "pipeline" / "llm_synthesis" / "synthesize.py")
    cmd = [sys.executable, "-c", BLOCK_DB, script, *args] if block_db else [sys.executable, script, *args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=repo)


def test_eval_run_leaves_production_state_untouched(repo, tmp_path):
    ext = tmp_path / "elsewhere" / "analysis.json"
    ext.parent.mkdir()
    a2 = rich_analysis()
    a2["sample"]["sha256"] = SHA2
    ext.write_text(json.dumps(a2))

    before = snapshot(repo)
    p1 = synth(repo, SHA, "--eval", "t1", "--dry-run", "--skip-checkpoint")
    assert p1.returncode == 0, p1.stdout + p1.stderr
    p2 = synth(repo, SHA2, "--eval", "t1", "--analysis", str(ext), "--dry-run", "--skip-checkpoint")
    assert p2.returncode == 0, p2.stdout + p2.stderr
    assert snapshot(repo) == before

    ev = repo / "output" / "eval" / "t1"
    runs = sorted((ev / "runs").iterdir())
    assert len(runs) == 2 and len(list((ev / "bundles").iterdir())) == 2
    for run in runs:
        m = json.loads((run / "manifest.json").read_text())
        assert m["mode"] == "eval" and m["eval_label"] == "t1" and m["status"] == "ok"
        assert (run / "synthesis.json").exists()
        assert m["bundle"]["path"].startswith("output/eval/t1/bundles/")
    assert "EVAL 't1' complete" in p1.stdout


def test_control_prod_dry_run_does_write(repo):
    """Proves the snapshot would catch a write: a normal dry run changes reports."""
    before = snapshot(repo)
    p = synth(repo, SHA, "--dry-run", "--skip-checkpoint", block_db=False)
    assert p.returncode == 0, p.stdout + p.stderr
    after = snapshot(repo)
    assert after != before
    assert after[f"output/reports/{SHA}.synthesis.json"] != before[f"output/reports/{SHA}.synthesis.json"]


@pytest.mark.parametrize("args", [
    ("--all", "--eval", "t1", "--dry-run"),
    (SHA, "--analysis", "/tmp/x.json", "--dry-run"),
    (SHA, "--eval", "../escape", "--dry-run"),
    (SHA, "--eval", "a/b", "--dry-run"),
])
def test_bad_eval_invocations_exit_2(repo, args):
    before = snapshot(repo)
    p = synth(repo, *args, block_db=False)
    assert p.returncode == 2, p.stdout + p.stderr
    assert snapshot(repo) == before
