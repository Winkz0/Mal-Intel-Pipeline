"""Shared helpers for the D2.6 tests: requests, a Vivo queue, fake ssh/scp."""

import json
import os
import stat
import sys
from pathlib import Path

from pipeline.llm_synthesis import desktop_queue
from pipeline.llm_synthesis.bundle import build_bundle, save_bundle
from pipeline.llm_synthesis.prompt_builder import render

REPO = Path(__file__).resolve().parents[1]
VIVO = REPO / "vivo"
sys.path.insert(0, str(VIVO / "synthesis_queue_mcp"))
sys.path.insert(0, str(VIVO))

FAKE_SSH = """
import os, subprocess, sys
p = subprocess.run(["bash", "-c", sys.argv[2]], cwd=os.environ["FAKE_REMOTE_HOME"], capture_output=True, text=True)
sys.stdout.write(p.stdout); sys.stderr.write(p.stderr); sys.exit(p.returncode)
"""

FAKE_SCP = """
import os, re, shutil, sys
home = os.environ["FAKE_REMOTE_HOME"]
def resolve(arg):
    m = re.match(r"^[^/:@]+@[^/:]+:(.*)$", arg)   # user@host:path is remote
    return os.path.join(home, m.group(1)) if m else arg
src, dst = resolve(sys.argv[1]), resolve(sys.argv[2])
if not os.path.exists(src):
    sys.stderr.write("scp: " + sys.argv[1] + ": No such file or directory\\n"); sys.exit(1)
shutil.copyfile(src, dst)
"""


def make_queue_request(qdir: Path, bdir: Path, analysis: dict, notes: str = "", eval_label=None):
    """Pipeline-side export of one request. Returns (bundle_sha, request_path)."""
    b = build_bundle(analysis, analyst_notes=notes)
    sha, _ = save_bundle(b, bdir)
    path, _ = desktop_queue.export_request(qdir, sha, render(b), analysis["sample"],
                                           analyst_notes_present=bool(notes),
                                           mode="eval" if eval_label else "prod", eval_label=eval_label)
    return sha, path


def fake_tools(tmp: Path, monkeypatch, remote_home: Path) -> dict:
    (tmp / "fake_ssh.py").write_text(FAKE_SSH)
    (tmp / "fake_scp.py").write_text(FAKE_SCP)
    monkeypatch.setenv("FAKE_REMOTE_HOME", str(remote_home))
    return {"ssh": [sys.executable, str(tmp / "fake_ssh.py")], "scp": [sys.executable, str(tmp / "fake_scp.py")]}


def write_config(vivo_queue: Path, tools: dict, remote_repo: str = "repo"):
    vivo_queue.mkdir(parents=True, exist_ok=True)
    (vivo_queue / "queue.config.json").write_text(json.dumps(
        {"pipeline_host": "analyst@pipeline", "remote_repo": remote_repo, **tools}))


def make_writable(path: Path):
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
