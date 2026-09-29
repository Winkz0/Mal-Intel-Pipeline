#!/usr/bin/env python3
"""Revert REMnux to its clean-baseline snapshot through the Proxmox API.

Cycle: stop -> rollback -> start -> wait until SSH answers.

Runs from the pipeline VM with an API token scoped to VM.Audit,
VM.PowerMgmt and VM.Snapshot.Rollback on /vms/<REMNUX_VMID> only. It can
roll REMnux back and power-cycle it; it cannot change REMnux's config
(including its network) or touch any other VM.

Config is read from config/secrets.env, the same file the rest of the
pipeline uses. Only PVE_TOKEN_SECRET is required; the rest have defaults:

    PVE_TOKEN_SECRET=<token value>
    PVE_TOKEN_ID=remnux-revert@pve!pipeline
    PVE_API_URL=https://<pve-host>:8006/api2/json
    PVE_CA_PATH=~/.config/pve/pve-root-ca.pem
    PVE_NODE=<pve-node>
    REMNUX_VMID=<vmid>
    REMNUX_SNAPSHOT=clean-baseline
    REMNUX_SSH_HOST=remnux

Usage:
    python scripts/remnux_revert.py             # full revert, waits for SSH
    python scripts/remnux_revert.py --check     # read-only: token, snapshot, status
    python scripts/remnux_revert.py --no-start  # roll back, leave REMnux powered off
"""
from __future__ import annotations

import argparse
import json
import logging
import os
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

API_URL = os.getenv("PVE_API_URL", "https://<pve-host>:8006/api2/json").rstrip("/")
CA_PATH = Path(os.path.expanduser(os.getenv("PVE_CA_PATH", "~/.config/pve/pve-root-ca.pem")))
TOKEN_ID = os.getenv("PVE_TOKEN_ID", "remnux-revert@pve!pipeline")
TOKEN_SECRET = os.getenv("PVE_TOKEN_SECRET", "")
NODE = os.getenv("PVE_NODE", "<pve-node>")
VMID = os.getenv("REMNUX_VMID", "<vmid>")
SNAPSHOT = os.getenv("REMNUX_SNAPSHOT", "clean-baseline")
SSH_HOST = os.getenv("REMNUX_SSH_HOST", "remnux")

TASK_TIMEOUT = 180  # seconds for any single stop / rollback / start task

log = logging.getLogger("remnux_revert")


class RevertError(RuntimeError):
    """Any failure in the revert cycle."""


# --- Proxmox API -------------------------------------------------------------

def _context() -> ssl.SSLContext:
    """TLS context pinned to the node's own CA; verification stays on."""
    if not TOKEN_SECRET:
        raise RevertError("PVE_TOKEN_SECRET is not set (config/secrets.env)")
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


# --- Entry points ------------------------------------------------------------

def revert_remnux(start: bool = True, ssh_timeout: int = 180) -> float:
    """Roll REMnux back to SNAPSHOT. Returns elapsed seconds."""
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
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.check:
            check()
        else:
            elapsed = revert_remnux(start=not args.no_start, ssh_timeout=args.ssh_timeout)
            log.info("revert complete in %.0fs", elapsed)
    except RevertError as exc:
        log.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())