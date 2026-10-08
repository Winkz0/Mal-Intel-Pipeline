#!/usr/bin/env python3
"""Revert REMnux to its clean-baseline snapshot through the Proxmox API.

Cycle: stop -> rollback -> start -> wait until SSH answers.

Runs from the pipeline VM with an API token scoped to VM.Audit,
VM.PowerMgmt and VM.Snapshot.Rollback on /vms/<REMNUX_VMID> only. It can
roll REMnux back and power-cycle it; it cannot change REMnux's config
(including its network) or touch any other VM.

Config is read from config/secrets.env, the same file the rest of the
pipeline uses. These four are required; the script stops if any is missing:

    PVE_TOKEN_SECRET=<token value>
    PVE_API_URL=https://<pve-host>:8006/api2/json
    PVE_NODE=<pve-node>
    REMNUX_VMID=<vmid>

The rest have defaults:

    PVE_TOKEN_ID=remnux-revert@pve!pipeline
    PVE_CA_PATH=~/.config/pve/pve-root-ca.pem
    REMNUX_SNAPSHOT=clean-baseline
    REMNUX_SSH_HOST=remnux
    REMNUX_REPO=/home/remnux/Mal-Intel-Pipeline
    REMNUX_VENV=venv_remnux

Usage:
    python scripts/remnux_revert.py             # full revert, waits for SSH
    python scripts/remnux_revert.py --deploy    # full revert, then deploy committed pipeline/
    python scripts/remnux_revert.py --check     # read-only: token, snapshot, status
    python scripts/remnux_revert.py --no-start  # roll back, leave REMnux powered off

--deploy copies `git archive HEAD pipeline` from this repo onto REMnux, records
the commit in DEPLOYED_COMMIT, and smoke-tests the import with REMNUX_VENV. The
snapshot then only has to change for tools and venvs, and REMnux never runs code
that isn't committed. Uncommitted changes under pipeline/ are reported, not sent.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / "config" / "secrets.env")

API_URL = os.getenv("PVE_API_URL", "").rstrip("/")
CA_PATH = Path(os.path.expanduser(os.getenv("PVE_CA_PATH", "~/.config/pve/pve-root-ca.pem")))
TOKEN_ID = os.getenv("PVE_TOKEN_ID", "remnux-revert@pve!pipeline")
TOKEN_SECRET = os.getenv("PVE_TOKEN_SECRET", "")
NODE = os.getenv("PVE_NODE", "")
VMID = os.getenv("REMNUX_VMID", "")
SNAPSHOT = os.getenv("REMNUX_SNAPSHOT", "clean-baseline")
SSH_HOST = os.getenv("REMNUX_SSH_HOST", "remnux")
REMNUX_REPO = os.getenv("REMNUX_REPO", "/home/remnux/Mal-Intel-Pipeline")
REMNUX_VENV = os.getenv("REMNUX_VENV", "venv_remnux")

TASK_TIMEOUT = 180  # seconds for any single stop / rollback / start task

log = logging.getLogger("remnux_revert")


class RevertError(RuntimeError):
    """Any failure in the revert cycle."""


# --- Proxmox API -------------------------------------------------------------

def _require_settings() -> None:
    """Host, node and VMID have no defaults, so homelab addresses stay out of the repo."""
    missing = [name for name, value in (("PVE_TOKEN_SECRET", TOKEN_SECRET), ("PVE_API_URL", API_URL),
                                        ("PVE_NODE", NODE), ("REMNUX_VMID", VMID)) if not value]
    if missing:
        raise RevertError(f"not set in config/secrets.env: {', '.join(missing)}")
    if not API_URL.startswith("https://"):
        raise RevertError("PVE_API_URL must be an https:// URL")
    if not VMID.isdigit():
        raise RevertError("REMNUX_VMID must be a number")


def _context() -> ssl.SSLContext:
    """TLS context pinned to the node's own CA; verification stays on."""
    _require_settings()
    if not CA_PATH.is_file():
        raise RevertError(f"CA file not found: {CA_PATH}")
    return ssl.create_default_context(cafile=str(CA_PATH))


def _api(method: str, path: str, ctx: ssl.SSLContext):
    req = urllib.request.Request(f"{API_URL}{path}", method=method)
    req.add_header("Authorization", f"PVEAPIToken={TOKEN_ID}={TOKEN_SECRET}")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.load(resp).get("data")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        raise RevertError(f"{method} {path} -> HTTP {exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise RevertError(f"{method} {path} -> {exc.reason}") from None


def _vm(suffix: str) -> str:
    return f"/nodes/{NODE}/qemu/{VMID}{suffix}"


def vm_status(ctx: ssl.SSLContext) -> str:
    return _api("GET", _vm("/status/current"), ctx)["status"]


def snapshot_exists(ctx: ssl.SSLContext) -> bool:
    snaps = _api("GET", _vm("/snapshot"), ctx) or []
    return any(s.get("name") == SNAPSHOT for s in snaps)


def _wait_task(upid: str, ctx: ssl.SSLContext) -> None:
    """Poll a Proxmox task until it finishes; raise unless it ended OK."""
    path = f"/nodes/{NODE}/tasks/{urllib.parse.quote(upid, safe=':@!')}/status"
    deadline = time.monotonic() + TASK_TIMEOUT
    while time.monotonic() < deadline:
        task = _api("GET", path, ctx)
        if task.get("status") == "stopped":
            if task.get("exitstatus") != "OK":
                raise RevertError(f"task {task.get('type')} failed: {task.get('exitstatus')}")
            return
        time.sleep(2)
    raise RevertError(f"task still running after {TASK_TIMEOUT}s: {upid}")


def _run(suffix: str, ctx: ssl.SSLContext, label: str) -> None:
    upid = _api("POST", _vm(suffix), ctx)
    log.info("%s: %s", label, upid)
    _wait_task(upid, ctx)


# --- SSH readiness -----------------------------------------------------------

def wait_for_ssh(timeout: int) -> None:
    """Revert is a cold boot; don't hand REMnux back until SSH answers."""
    deadline = time.monotonic() + timeout
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", SSH_HOST, "true"]
    while time.monotonic() < deadline:
        try:
            if subprocess.run(cmd, capture_output=True, timeout=15).returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(3)
    raise RevertError(f"{SSH_HOST} did not answer SSH within {timeout}s")


# --- Code deploy -------------------------------------------------------------

def _git(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(REPO_ROOT), *args],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RevertError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def deploy_code() -> str:
    """Replace REMnux's pipeline/ with the committed tree. Returns the short commit."""
    commit = _git("rev-parse", "--short", "HEAD")
    if _git("status", "--porcelain", "--", "pipeline"):
        log.warning("uncommitted changes under pipeline/ are NOT deployed; deploying HEAD %s",
                    commit)

    repo = shlex.quote(REMNUX_REPO)
    remote = (
        f"set -e; cd {repo}; rm -rf pipeline; tar xf -; "
        f"printf '%s\\n' {shlex.quote(commit)} > DEPLOYED_COMMIT; "
        f"{shlex.quote(REMNUX_VENV)}/bin/python -c 'import pipeline.static_analysis.analyze'; "
        "rm -f pipeline.db"  # the import creates an empty DB via init_db()
    )
    archive = subprocess.Popen(["git", "-C", str(REPO_ROOT), "archive", "HEAD", "pipeline"],
                               stdout=subprocess.PIPE)
    try:
        result = subprocess.run(["ssh", "-o", "BatchMode=yes", SSH_HOST, remote],
                                stdin=archive.stdout, capture_output=True, text=True,
                                timeout=120)
    except subprocess.TimeoutExpired:
        archive.kill()
        raise RevertError(f"deploy to {SSH_HOST} timed out after 120s") from None
    finally:
        archive.stdout.close()
        archive_rc = archive.wait()
    # Report the remote side first: if ssh died early, git archive only sees a broken pipe
    if result.returncode != 0:
        raise RevertError(f"deploy to {SSH_HOST} failed: {result.stderr.strip()[-400:]}")
    if archive_rc != 0:
        raise RevertError("git archive failed")
    return commit


# --- Entry points ------------------------------------------------------------

def revert_remnux(start: bool = True, ssh_timeout: int = 180, deploy: bool = False) -> float:
    """Roll REMnux back to SNAPSHOT, optionally deploy committed code. Returns elapsed seconds."""
    ctx = _context()
    began = time.monotonic()

    if not snapshot_exists(ctx):
        raise RevertError(f"snapshot '{SNAPSHOT}' not found on VM {VMID}")

    if vm_status(ctx) != "stopped":
        _run("/status/stop", ctx, "stop")  # hard stop: state is discarded anyway
    _run(f"/snapshot/{urllib.parse.quote(SNAPSHOT, safe='')}/rollback", ctx, "rollback")

    if start:
        _run("/status/start", ctx, "start")
        wait_for_ssh(ssh_timeout)
        log.info("%s answering SSH", SSH_HOST)
        if deploy:
            log.info("deployed pipeline/ at %s; import check passed", deploy_code())

    return time.monotonic() - began


def check() -> None:
    """Read-only: token accepted, snapshot present, current VM state."""
    ctx = _context()
    log.info("token accepted; VM %s is %s", VMID, vm_status(ctx))
    if not snapshot_exists(ctx):
        raise RevertError(f"snapshot '{SNAPSHOT}' not found on VM {VMID}")
    log.info("snapshot '%s' present", SNAPSHOT)


def main() -> int:
    parser = argparse.ArgumentParser(description="Revert REMnux to its clean-baseline snapshot.")
    parser.add_argument("--check", action="store_true",
                        help="read-only: verify token, snapshot and VM status")
    parser.add_argument("--no-start", action="store_true",
                        help="roll back and leave REMnux powered off")
    parser.add_argument("--ssh-timeout", type=int, default=180,
                        help="seconds to wait for SSH after start (default: 180)")
    parser.add_argument("--deploy", action="store_true",
                        help="after the revert, deploy committed pipeline/ code to REMnux")
    args = parser.parse_args()
    if args.deploy and (args.no_start or args.check):
        parser.error("--deploy needs a running REMnux; it can't be combined with --no-start or --check")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.check:
            check()
        else:
            elapsed = revert_remnux(start=not args.no_start, ssh_timeout=args.ssh_timeout,
                                    deploy=args.deploy)
            log.info("revert complete in %.0fs", elapsed)
    except RevertError as exc:
        log.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())