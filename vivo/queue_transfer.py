"""
queue_transfer.py
M13 v2 (D2.6): move synthesis requests and answers between pipeline and the Vivo.

The Vivo always initiates (ssh/scp to pipeline); pipeline never connects to the
Vivo.

    pull    copy <remote queue>/pending/*.request.json into inbox/, verify each,
            record its SHA-256 in inbox/.pull-record.json, mark it read-only
    push    refuse if any inbox request changed since pull; copy each answer in
            outbox/ to <remote queue>/returned/, confirm the remote SHA-256,
            then delete the local answer and its request
    status  what's waiting, answered, recorded

Config: <queue>/queue.config.json (untracked; keeps homelab addresses out of the
public repo). Example in vivo/queue.config.example.json:
    {"pipeline_host": "user@host", "remote_repo": "Mal-Intel-Pipeline"}
Optional "ssh" / "scp" keys override the commands (lists).

Usage (Vivo, PowerShell, venv python):
    python vivo\\queue_transfer.py pull   [--eval LABEL] [--dry-run]
    python vivo\\queue_transfer.py push   [--dry-run]
    python vivo\\queue_transfer.py status
--queue defaults to C:\\Tools\\Dev\\synthesis-queue.
"""

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "synthesis_queue_mcp"))

from queue_core import (  # noqa: E402
    RECORD_NAME,
    REQUEST_NAME,
    prompt_hash,
    read_record,
    sha256_file,
    write_json_atomic,
)

DEFAULT_QUEUE = Path(r"C:\Tools\Dev\synthesis-queue")
SAFE_REMOTE = re.compile(r"^[A-Za-z0-9._~/-]+$")
ANSWER_NAME = re.compile(r"^([0-9a-f]{64})\.synthesis\.json$")


class TransferError(Exception):
    pass


def load_config(queue: Path) -> dict:
    path = queue / "queue.config.json"
    if not path.exists():
        raise TransferError(f"missing {path} (copy vivo/queue.config.example.json there and fill it in)")
    cfg = json.loads(path.read_text(encoding="utf-8"))
    for key in ("pipeline_host", "remote_repo"):
        if not isinstance(cfg.get(key), str) or not cfg[key]:
            raise TransferError(f"config needs '{key}'")
    if not SAFE_REMOTE.match(cfg["remote_repo"]) or ".." in cfg["remote_repo"].split("/"):
        raise TransferError("remote_repo may contain only letters, digits and . _ ~ / -")
    if not re.match(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.:_-]+$|^[A-Za-z0-9._-]+$", cfg["pipeline_host"]):
        raise TransferError("pipeline_host must look like user@host or an ssh config alias")
    cfg.setdefault("ssh", ["ssh"])
    cfg.setdefault("scp", ["scp"])
    return cfg


def remote_queue(cfg: dict, eval_label: str = None) -> str:
    base = cfg["remote_repo"].rstrip("/")
    if eval_label:
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", eval_label) or ".." in eval_label:
            raise TransferError("bad eval label")
        return f"{base}/output/eval/{eval_label}/queue"
    return f"{base}/output/queue"


class Transfer:
    def __init__(self, queue: Path, cfg: dict, dry_run: bool = False, out=print):
        self.queue, self.cfg, self.dry_run, self.out = Path(queue), cfg, dry_run, out
        self.inbox, self.outbox = self.queue / "inbox", self.queue / "outbox"
        self.host = cfg["pipeline_host"]

    def _run(self, cmd: list, cwd: Path = None, mutating: bool = True) -> str:
        if self.dry_run and mutating:
            self.out(f"  [dry-run] {' '.join(cmd)}")
            return ""
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=180)
        if p.returncode != 0:
            raise TransferError(f"{cmd[0]} failed ({p.returncode}): {(p.stderr or p.stdout).strip()[:300]}")
        return p.stdout

    def ssh(self, command: str, mutating: bool = True) -> str:
        return self._run([*self.cfg["ssh"], self.host, command], mutating=mutating)

    def scp(self, src: str, dst: str, cwd: Path) -> None:
        self._run([*self.cfg["scp"], src, dst], cwd=cwd)

    # ── pull ────────────────────────────────────────────────────────────────

    def pull(self, eval_label: str = None) -> int:
        rq = remote_queue(self.cfg, eval_label)
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.outbox.mkdir(parents=True, exist_ok=True)
        listing = self.ssh(f"ls -1 {rq}/pending 2>/dev/null || true", mutating=False)
        names = [n.strip() for n in listing.splitlines() if REQUEST_NAME.match(n.strip())]
        record = read_record(self.inbox)
        pulled = 0
        for name in names:
            sha = REQUEST_NAME.match(name).group(1)
            if (self.inbox / name).exists() or (self.outbox / f"{sha}.synthesis.json").exists():
                continue
            part = f".{name}.part"
            self.scp(f"{self.host}:{rq}/pending/{name}", part, cwd=self.inbox)
            if self.dry_run:
                continue
            part_path = self.inbox / part
            try:
                req = json.loads(part_path.read_text(encoding="utf-8"))
                ok = (isinstance(req, dict) and req.get("bundle_sha256") == sha
                      and isinstance(req.get("prompt"), str)
                      and prompt_hash(req["prompt"]) == req.get("prompt_sha256"))
            except (OSError, json.JSONDecodeError):
                ok = False
            if not ok:
                part_path.unlink(missing_ok=True)
                self.out(f"  [!] {sha[:16]}...: request failed verification; not pulled")
                continue
            final = self.inbox / name
            part_path.replace(final)
            record[name] = {"sha256": sha256_file(final), "remote_queue": rq,
                            "pulled_at": datetime.now(timezone.utc).isoformat()}
            os.chmod(final, stat.S_IREAD)  # read-only attribute on Windows
            pulled += 1
            self.out(f"  [+] pulled {sha[:16]}...")
        if not self.dry_run:
            write_json_atomic(self.inbox / RECORD_NAME, record)
        self.out(f"pull: {pulled} new request(s) from {rq}")
        return pulled

    # ── push ────────────────────────────────────────────────────────────────

    def verify_inbox(self) -> dict:
        record = read_record(self.inbox)
        present = {p.name for p in self.inbox.glob("*.request.json")} if self.inbox.is_dir() else set()
        problems = [f"unrecorded file in inbox: {n}" for n in sorted(present - set(record))]
        problems += [f"recorded request missing: {n}" for n in sorted(set(record) - present)]
        for name in sorted(present & set(record)):
            if sha256_file(self.inbox / name) != record[name]["sha256"]:
                problems.append(f"changed since pull: {name}")
        if problems:
            raise TransferError("inbox does not match the pull record; not pushing:\n  " + "\n  ".join(problems))
        return record

    def push(self) -> int:
        record = self.verify_inbox()
        answers = sorted(p for p in self.outbox.glob("*.synthesis.json") if ANSWER_NAME.match(p.name)) \
            if self.outbox.is_dir() else []
        pushed = 0
        for ans in answers:
            sha = ANSWER_NAME.match(ans.name).group(1)
            req_name = f"{sha}.request.json"
            rec = record.get(req_name)
            if rec is None:
                self.out(f"  [!] {sha[:16]}...: answer has no pulled request; left in outbox")
                continue
            rq = rec["remote_queue"]
            if not SAFE_REMOTE.match(rq):
                raise TransferError("unsafe remote queue path in pull record")
            local_hash = sha256_file(ans)
            self.ssh(f"mkdir -p {rq}/returned")
            self.scp(ans.name, f"{self.host}:{rq}/returned/{ans.name}", cwd=self.outbox)
            if self.dry_run:
                continue
            remote = self.ssh(f"sha256sum {rq}/returned/{ans.name}", mutating=False).split()
            if not remote or remote[0] != local_hash:
                self.out(f"  [!] {sha[:16]}...: remote copy hash mismatch; local files kept")
                continue
            ans.unlink()
            req_path = self.inbox / req_name
            if req_path.exists():
                os.chmod(req_path, stat.S_IWRITE | stat.S_IREAD)
                req_path.unlink()
            record.pop(req_name, None)
            write_json_atomic(self.inbox / RECORD_NAME, record)
            pushed += 1
            self.out(f"  [+] pushed {sha[:16]}... -> {rq}/returned/")
        self.out(f"push: {pushed} answer(s) delivered")
        return pushed

    # ── status ──────────────────────────────────────────────────────────────

    def status(self) -> None:
        record = read_record(self.inbox)
        reqs = sorted(self.inbox.glob("*.request.json")) if self.inbox.is_dir() else []
        answered = {p.name.split(".")[0] for p in self.outbox.glob("*.synthesis.json")} if self.outbox.is_dir() else set()
        for p in reqs:
            sha = p.name.split(".")[0]
            state = "answered" if sha in answered else "waiting"
            where = record.get(p.name, {}).get("remote_queue", "unrecorded")
            self.out(f"  {state:<9} {sha[:16]}...  from {where}")
        self.out(f"status: {len(reqs)} in inbox, {len(answered)} answer(s) in outbox")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Move synthesis requests/answers between pipeline and the Vivo")
    ap.add_argument("action", choices=("pull", "push", "status"))
    ap.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    ap.add_argument("--eval", metavar="LABEL", help="pull from the pipeline's eval queue for LABEL")
    ap.add_argument("--dry-run", action="store_true", help="print copy/delete commands instead of running them")
    args = ap.parse_args(argv)
    try:
        t = Transfer(args.queue, load_config(args.queue), dry_run=args.dry_run)
        if args.action == "pull":
            t.pull(args.eval)
        elif args.action == "push":
            t.push()
        else:
            t.status()
    except TransferError as e:
        print(f"[!] {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
