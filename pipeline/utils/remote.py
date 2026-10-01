"""
remote.py
SSH/SFTP communication with the REMnux VM via paramiko.
Handles file transfers and remote command execution
over the isolated analysis network (vmbr1).

CLI:
    python -m pipeline.utils.remote test            Test REMnux connectivity
    python -m pipeline.utils.remote push <sha256>   Push quarantined zip + meta.json to REMnux
    python -m pipeline.utils.remote pull [sha256]   Pull one (or all) analysis JSONs from REMnux
"""

import logging
import os
from pathlib import Path

import paramiko

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]

# REMnux connection defaults (override via environment if the layout changes)
REMNUX_HOST = os.getenv("REMNUX_HOST", "10.10.10.10")
REMNUX_USER = os.getenv("REMNUX_USER", "remnux")
REMNUX_KEY = Path(os.path.expanduser(os.getenv("REMNUX_KEY", "~/.ssh/id_ed25519_remnux")))
REMNUX_REPO = os.getenv("REMNUX_REPO", "/home/remnux/Mal-Intel-Pipeline")
KNOWN_HOSTS = Path(os.path.expanduser(os.getenv("REMNUX_KNOWN_HOSTS", "~/.ssh/known_hosts")))


def _get_client() -> paramiko.SSHClient:
    """
    Create and return a connected SSH client.

    REMnux is the untrusted side of this link, so its host key must already be
    in known_hosts (recorded on the first manual `ssh remnux`); an unknown or
    changed key is rejected rather than silently accepted.
    """
    client = paramiko.SSHClient()
    client.load_host_keys(str(KNOWN_HOSTS))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        hostname=REMNUX_HOST,
        username=REMNUX_USER,
        key_filename=str(REMNUX_KEY),
        allow_agent=False,
        look_for_keys=False,
        timeout=10,
    )
    return client


def test_connection() -> bool:
    """Test SSH connectivity to REMnux. Returns True if successful."""
    try:
        client = _get_client()
        stdin, stdout, stderr = client.exec_command("echo connected")
        result = stdout.read().decode().strip()
        client.close()
        if result == "connected":
            logger.info("REMnux connection OK")
            return True
        return False
    except Exception as e:
        logger.error(f"REMnux connection failed: {e}")
        return False


def run_command(command: str, timeout: int = 30) -> dict:
    """
    Execute a command on REMnux via SSH.
    Returns dict with stdout, stderr, and return code.
    """
    try:
        client = _get_client()
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        result = {
            "stdout": stdout.read().decode(),
            "stderr": stderr.read().decode(),
            "returncode": stdout.channel.recv_exit_status(),
        }
        client.close()
        return result
    except Exception as e:
        logger.error(f"Remote command failed: {e}")
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def push_file(local_path: str, remote_path: str) -> bool:
    """SCP a file from host to REMnux."""
    try:
        client = _get_client()
        sftp = client.open_sftp()
        sftp.put(str(local_path), str(remote_path))
        sftp.close()
        client.close()
        logger.info(f"Pushed: {local_path} -> {remote_path}")
        return True
    except Exception as e:
        logger.error(f"Push failed: {e}")
        return False


def pull_file(remote_path: str, local_path: str) -> bool:
    """SCP a file from REMnux to host."""
    try:
        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)
        client = _get_client()
        sftp = client.open_sftp()
        sftp.get(str(remote_path), str(local_path))
        sftp.close()
        client.close()
        logger.info(f"Pulled: {remote_path} -> {local_path}")
        return True
    except Exception as e:
        logger.error(f"Pull failed: {e}")
        return False


def push_sample(sha256: str) -> bool:
    """
    Push a quarantined sample (encrypted zip + meta.json sidecar) to REMnux's
    quarantine. The zip stays encrypted in transit and at rest; analyze.py
    extracts it to a RAM disk on REMnux and wipes it afterwards.
    """
    quarantine = REPO_ROOT / "samples" / "quarantine"
    remote_quarantine = f"{REMNUX_REPO}/samples/quarantine"
    files = [quarantine / f"{sha256}.zip", quarantine / f"{sha256}.meta.json"]

    missing = [f.name for f in files if not f.exists()]
    if missing:
        logger.error(f"Not in local quarantine: {', '.join(missing)}")
        return False

    for f in files:
        if not push_file(str(f), f"{remote_quarantine}/{f.name}"):
            return False
    return True


def pull_analysis(sha256: str = None) -> list[str]:
    """
    Pull analysis JSON(s) from REMnux to host.
    If sha256 provided, pulls that specific file.
    If None, pulls all .analysis.json files.
    Returns list of local paths that were written.
    """
    local_dir = REPO_ROOT / "output" / "analysis"
    local_dir.mkdir(parents=True, exist_ok=True)
    remote_dir = f"{REMNUX_REPO}/output/analysis"
    pulled = []

    try:
        client = _get_client()
        sftp = client.open_sftp()

        if sha256:
            # Pull specific file
            remote_file = f"{remote_dir}/{sha256}.analysis.json"
            local_file = str(local_dir / f"{sha256}.analysis.json")
            sftp.get(remote_file, local_file)
            pulled.append(local_file)
            logger.info(f"Pulled analysis: {sha256[:16]}...")
        else:
            # Pull all analysis files
            try:
                remote_files = sftp.listdir(remote_dir)
            except FileNotFoundError:
                logger.warning(f"Remote directory not found: {remote_dir}")
                sftp.close()
                client.close()
                return pulled

            for fname in remote_files:
                if fname.endswith(".analysis.json"):
                    remote_file = f"{remote_dir}/{fname}"
                    local_file = str(local_dir / fname)
                    sftp.get(remote_file, local_file)
                    pulled.append(local_file)

            logger.info(f"Pulled {len(pulled)} analysis file(s)")

        sftp.close()
        client.close()
    except Exception as e:
        logger.error(f"Pull analysis failed: {e}")

    return pulled


def push_checkpoint() -> bool:
    """
    Push the most recent approved manifest to REMnux.
    """
    checkpoint_dir = REPO_ROOT / "checkpoints"
    manifests = sorted(checkpoint_dir.glob("checkpoint1_*.json"), reverse=True)

    if not manifests:
        logger.error("No approved manifest found in checkpoints/")
        return False

    manifest = manifests[0]
    remote_path = f"{REMNUX_REPO}/checkpoints/{manifest.name}"

    print(f"  [*] Pushing {manifest.name} to REMnux...")
    success = push_file(str(manifest), remote_path)
    if success:
        print("  [+] Done")
    return success


def list_remote_analyses() -> list[str]:
    """List all analysis JSON filenames on REMnux."""
    result = run_command(f"ls {REMNUX_REPO}/output/analysis/*.analysis.json 2>/dev/null")
    if result["returncode"] != 0:
        return []
    return [Path(line).name for line in result["stdout"].strip().split("\n") if line]


if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="Transfer helper for the REMnux analysis VM")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("test", help="test SSH connectivity to REMnux")
    p_push = sub.add_parser("push", help="push a quarantined sample (zip + meta.json) to REMnux")
    p_push.add_argument("sha256")
    p_pull = sub.add_parser("pull", help="pull analysis JSON(s) from REMnux")
    p_pull.add_argument("sha256", nargs="?", help="omit to pull all")
    args = parser.parse_args()

    if args.cmd == "test":
        ok = test_connection()
        print("[+] REMnux connection successful" if ok else "[!] REMnux connection failed")
    elif args.cmd == "push":
        ok = push_sample(args.sha256)
    else:
        pulled = pull_analysis(args.sha256)
        ok = bool(pulled)
        print(f"[+] {len(pulled)} analysis file(s) pulled" if ok else "[!] Pull failed")

    sys.exit(0 if ok else 1)