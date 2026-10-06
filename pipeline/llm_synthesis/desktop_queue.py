"""
desktop_queue.py
M13 v2 (D2.6): the Desktop inbox engine, pipeline side.

Export (synthesize.py --engine desktop): after checkpoint #2 the rendered prompt
is written to <queue>/pending/<bundle_sha>.request.json. The Vivo pulls it
(vivo/queue_transfer.py), Claude Desktop answers it through the two-tool
synthesis-queue MCP server, and the Vivo pushes the answer to
<queue>/returned/<bundle_sha>.synthesis.json. The pipeline never connects to
the Vivo.

Import (scripts/queue_import.py): every returned file is treated as untrusted.
It must name a pending request, carry the same bundle hash, and the stored
bundle must still render to the exact prompt that was exported. It is then run
through synthesizer.run_synthesis with a replay engine, so it gets the same
schema validation, YARA clean-up, manifest and run directory as an API run.

<queue> is output/queue/ in production and output/eval/<label>/queue/ in eval.
"""

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from pipeline.llm_synthesis import manifest as mf
from pipeline.llm_synthesis.bundle import BundleError, load_bundle
from pipeline.llm_synthesis.output_validation import load_schema, schema_for_template
from pipeline.llm_synthesis.prompt_builder import render
from pipeline.utils import run_context

REQUEST_VERSION = 1
ENGINE_ID = "desktop-mcp"
MAX_RETURNED_BYTES = 512 * 1024

_SHA = re.compile(r"^[0-9a-f]{64}$")
_RETURNED = re.compile(r"^([0-9a-f]{64})\.synthesis\.json$")

DESKTOP_DEFAULTS = {
    "engine": "Claude Desktop via the synthesis-queue MCP server (vivo/synthesis_queue_mcp)",
    "context": "app system prompt, Synthesis Queue project instructions and the get_bundle "
               "wrapper apply; not comparable to API runs for benchmark purposes",
    "model": "as selected in the Desktop app (recorded from --model on import)",
}


class QueueError(ValueError):
    pass


def queue_root(repo_root: Path, eval_label: str = None) -> Path:
    if eval_label:
        return run_context.eval_root(repo_root, eval_label) / "queue"
    return Path(repo_root) / "output" / "queue"


def bundle_dir_for(repo_root: Path, eval_label: str = None) -> Path:
    if eval_label:
        return run_context.eval_root(repo_root, eval_label) / "bundles"
    return Path(repo_root) / "output" / "bundles"


def _write_json_new(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".tmp-{path.name}")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    tmp.replace(path)


# ── export ──────────────────────────────────────────────────────────────────

def export_request(queue_dir: Path, bundle_sha: str, rendered, sample: dict,
                   analyst_notes_present: bool, mode: str, eval_label: str = None) -> tuple[Path, bool]:
    """Write pending/<bundle_sha>.request.json. Returns (path, created)."""
    if not _SHA.match(bundle_sha):
        raise QueueError("bad bundle hash")
    path = Path(queue_dir) / "pending" / f"{bundle_sha}.request.json"
    if path.exists():
        return path, False
    schema_id = schema_for_template(rendered.template_id)
    _, schema_sha = load_schema(schema_id)
    request = {
        "request_version": REQUEST_VERSION,
        "bundle_sha256": bundle_sha,
        "sample": {k: sample.get(k) for k in ("sha256", "file_name", "file_type", "malware_family", "tags")},
        "template": {"id": rendered.template_id, "sha256": rendered.template_sha256},
        "output_schema": {"id": schema_id, "sha256": schema_sha},
        "prompt_sha256": rendered.prompt_sha256,
        "prompt": rendered.prompt,
        "analyst_notes_present": analyst_notes_present,
        "mode": mode,
        "eval_label": eval_label,
        "created_at": mf.utc_now().isoformat(),
    }
    _write_json_new(path, request)
    with open(Path(queue_dir) / "exports.jsonl", "a", encoding="utf-8") as log:
        log.write(json.dumps({"bundle_sha256": bundle_sha, "sample_sha256": request["sample"]["sha256"],
                              "created_at": request["created_at"], "mode": mode}) + "\n")
    return path, True


# ── import ──────────────────────────────────────────────────────────────────

class ReplayEngine:
    """Hands an already-submitted Desktop answer to run_synthesis."""
    id = ENGINE_ID

    def __init__(self, returned: dict, model_reported: str):
        self.returned = returned
        self.model_reported = model_reported

    def run(self, prompt: str):
        from pipeline.llm_synthesis.engines import EngineResult
        return EngineResult(
            engine_id=self.id,
            text=json.dumps(self.returned["synthesis"]),
            raw=self.returned,
            model_reported=self.model_reported,
            params={},
            defaults_assumed=dict(DESKTOP_DEFAULTS),
            stop_reason="submitted",
            sdk=None,
        )


def _move(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return dst


def check_returned(path: Path, queue_dir: Path, bundle_dir: Path) -> tuple[dict, dict, dict, object]:
    """
    Integrity checks on one returned file. Returns (request, returned, bundle,
    rendered) or raises QueueError. Nothing is moved here.
    """
    m = _RETURNED.match(path.name)
    if not m:
        raise QueueError("file name is not <bundle_sha>.synthesis.json")
    sha = m.group(1)
    if path.stat().st_size > MAX_RETURNED_BYTES:
        raise QueueError(f"returned file larger than {MAX_RETURNED_BYTES} bytes")
    req_path = Path(queue_dir) / "pending" / f"{sha}.request.json"
    if not req_path.exists():
        raise QueueError("no pending request for this bundle (unknown, or already imported)")
    request = json.loads(req_path.read_text(encoding="utf-8"))
    try:
        returned = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise QueueError(f"returned file is not JSON: {e}") from None
    if not isinstance(returned, dict) or returned.get("bundle_sha256") != sha:
        raise QueueError("returned file's bundle_sha256 does not match its name")
    if not isinstance(returned.get("synthesis"), dict):
        raise QueueError("returned file has no synthesis object")
    if request.get("bundle_sha256") != sha:
        raise QueueError("pending request's bundle_sha256 does not match its name")
    try:
        bundle = load_bundle(Path(bundle_dir) / f"{sha}.json")
    except (OSError, BundleError) as e:
        raise QueueError(f"stored bundle missing or altered: {e}") from None
    rendered = render(bundle, request["template"]["id"])
    if rendered.template_sha256 != request["template"]["sha256"]:
        raise QueueError("template changed since export; re-export this sample")
    if rendered.prompt_sha256 != request["prompt_sha256"]:
        raise QueueError("bundle no longer renders to the exported prompt")
    return request, returned, bundle, rendered


def import_returned(queue_dir: Path, bundle_dir: Path, model_reported: str, runs_dir: Path = None,
                    mode: str = "prod", save=None) -> list[dict]:
    """
    Import every file in <queue>/returned/. `save(result)` is called for valid
    production results (synthesize.py's save + DB update); eval passes None.
    Returns one outcome dict per file.
    """
    from pipeline.llm_synthesis.synthesizer import run_synthesis

    queue_dir = Path(queue_dir)
    outcomes = []
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for path in sorted((queue_dir / "returned").glob("*")):
        if path.name.startswith(".") or not path.is_file():
            continue
        out = {"file": path.name, "status": None, "run": None, "error": None}
        try:
            request, returned, bundle, rendered = check_returned(path, queue_dir, bundle_dir)
        except (QueueError, OSError, KeyError, TypeError) as e:
            out.update(status="rejected", error=str(e))
            _move(path, queue_dir / "rejected" / f"{stamp}_{path.name}")
            outcomes.append(out)
            continue

        sha = request["bundle_sha256"]
        result = run_synthesis(
            analysis={"sample": request["sample"]},
            rendered=rendered,
            bundle_sha=sha,
            bundle_path=Path(bundle_dir) / f"{sha}.json",
            engine=ReplayEngine(returned, model_reported),
            cost_estimate=None,
            analyst_notes=bundle.get("analyst_notes", ""),
            runs_dir=runs_dir,
            mode=mode,
        )
        run_id = result["manifest"]["run_id"]
        out["run"] = result["manifest"]["path"]
        if result.get("error"):
            # Keep the request pending so a corrected answer can be pulled and submitted again.
            out.update(status="invalid", error=result["error"],
                       details=(result.get("validation_errors") or [])[:10])
            _move(path, queue_dir / "rejected" / f"{stamp}_{path.name}")
        else:
            if save is not None:
                save(result)
            _move(queue_dir / "pending" / f"{sha}.request.json", queue_dir / "imported" / f"{sha}.request.json")
            _move(path, queue_dir / "imported" / f"{sha}.{run_id}.synthesis.json")
            out["status"] = "imported"
        outcomes.append(out)
    return outcomes
