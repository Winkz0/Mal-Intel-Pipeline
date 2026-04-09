"""
remote.py
SSH/SCP communication with REMnux VM via paramiko.
Handles file transfers and remote command execution
over the isolated VMnet2 network.
"""

import logging
import os
from pathlib import Path

import paramiko

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]

# REMnux connection defaults
REMNUX_HOST = "10.10.10.10"
REMNUX_USER = "remnux"
REMNUX_KEY = Path.home() / ".ssh" / "remnux_key"
REMNUX_REPO = "/home/remnux/Mal-Intel-Pipeline"


def _get_client() -> paramiko.SSHClient:
    """Create and return a connected SSH client."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=REMNUX_HOST,
        username=REMNUX_USER,
        key_filename=str(REMNUX_KEY),
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
    manifests = sorted(checkpoint_dir.glob("approved_*.json"), reverse=True)

    if not manifests:
        logger.error("No approved manifest found in checkpoints/")
        return False

    manifest = manifests[0]
    remote_path = f"{REMNUX_REPO}/checkpoints/{manifest.name}"

    print(f"  [*] Pushing {manifest.name} to REMnux...")
    success = push_file(str(manifest), remote_path)
    if success:
        print(f"  [+] Done")
    return success


def list_remote_analyses() -> list[str]:
    """List all analysis JSON filenames on REMnux."""
    result = run_command(f"ls {REMNUX_REPO}/output/analysis/*.analysis.json 2>/dev/null")
    if result["returncode"] != 0:
        return []
    return [Path(line).name for line in result["stdout"].strip().split("\n") if line]