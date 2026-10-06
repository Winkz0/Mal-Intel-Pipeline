"""
manifest.py
M13 v2 (D2.2): one manifest per synthesis run.

Every run gets output/runs/<run_id>/ holding manifest.json, raw_response.json
when the engine returns one (the full API message, thinking blocks included), and
synthesis.json when the output validated (the run's own copy, so later runs of
the same sample can't overwrite what prompt_compare scores).
The manifest records everything needed to reproduce or audit the run: which
bundle and template produced the prompt, which engine and model answered, the
parameters sent, token usage and actual cost, timing, and the pipeline commit.
"""

import json
import os
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "output" / "runs"

# v2 (D2.4): adds synthesis_path; each run keeps its own validated synthesis.json.
MANIFEST_VERSION = 2

REQUIRED_KEYS = (
    "manifest_version", "run_id", "mode", "status", "error",
    "sample_sha256", "bundle", "template", "prompt_sha256", "output_schema",
    "engine", "model", "params", "defaults_assumed", "usage", "cost",
    "response", "timing", "raw_response_path", "validation",
    "analyst_notes_present", "pipeline", "synthesis_path",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_run_id(bundle_sha: str, engine_id: str, when: datetime = None) -> str:
    when = when or utc_now()
    return f"{when:%Y%m%dT%H%M%SZ}_{bundle_sha[:8]}_{engine_id}_{secrets.token_hex(2)}"


def pipeline_commit(repo_root: Path = REPO_ROOT) -> dict:
    """HEAD commit and whether tracked files differ from it. Never raises."""
    def git(*args):
        return subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True,
                              text=True, timeout=10, check=True).stdout.strip()
    try:
        commit = git("rev-parse", "HEAD")
    except Exception:
        deployed = repo_root / "DEPLOYED_COMMIT"
        commit = deployed.read_text().strip() if deployed.exists() else None
        return {"commit": commit, "dirty": None}
    try:
        dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    except Exception:
        dirty = None
    return {"commit": commit, "dirty": dirty}


def rel(path: Path, root: Path = REPO_ROOT) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def write_json_atomic(path: Path, obj) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=True)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return path


def build_manifest(**fields) -> dict:
    manifest = {"manifest_version": MANIFEST_VERSION, **fields}
    missing = [k for k in REQUIRED_KEYS if k not in manifest]
    if missing:
        raise ValueError(f"manifest missing keys: {missing}")
    json.dumps(manifest)  # must be serializable
    return manifest
