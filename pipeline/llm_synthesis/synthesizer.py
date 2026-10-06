"""
synthesizer.py
Runs one synthesis through an engine (engines/) and records it.

run_synthesis(): engine call -> raw response + manifest in output/runs/<run_id>/
-> JSON parse -> schema validation (output_validation) -> YARA string fix-up
-> report-compatible result dict. Output that fails validation is never returned
as a synthesis, so nothing downstream writes it to output/reports.
Engines never parse; this module never talks to an API directly.
"""

import json
import logging
import re
from pathlib import Path

from pipeline.llm_synthesis import manifest as mf
from pipeline.llm_synthesis.output_validation import schema_for_template, validate_output
from pipeline.llm_synthesis.pricing import actual_cost

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "output" / "reports"


def load_analysis(sha256: str) -> dict | None:
    analysis_path = REPO_ROOT / "output" / "analysis" / f"{sha256}.analysis.json"
    if not analysis_path.exists():
        # Try partial match
        matches = list((REPO_ROOT / "output" / "analysis").glob(f"{sha256}*.analysis.json"))
        if not matches:
            logger.error(f"Analysis file not found for: {sha256[:16]}...")
            return None
        analysis_path = matches[0]

    with open(analysis_path, "r") as f:
        return json.load(f)


def validate_yara_strings(yara_rule: str) -> str:
    """
    Drop string declarations the condition never references, so the rule
    compiles (YARA rejects unreferenced strings). A string counts as referenced
    when the condition names it with $, #, @ or !, matches a wildcard set such
    as ($prefix*), or uses `them`. Anonymous strings and multi-line
    declarations are left alone. Returns the (possibly modified) rule.

    Fixed in M13 v2: the previous version had the test inverted and removed
    the strings the condition *did* reference.
    """
    if not yara_rule or yara_rule == "[DRY RUN]":
        return yara_rule

    sections = re.search(r"\bstrings\s*:(.*?)\bcondition\s*:(.*)", yara_rule, re.DOTALL)
    if not sections:
        return yara_rule
    strings_text, condition_text = sections.group(1), sections.group(2)

    declared = re.findall(r"^\s*\$(\w+)\s*=", strings_text, re.MULTILINE)
    explicit = set(re.findall(r"[$#@!](\w+)(?![\w*])", condition_text))
    wildcards = re.findall(r"\$(\w*)\*", condition_text)

    undefined = sorted(n for n in explicit if n not in declared)
    if undefined:
        # The condition names strings that were never declared. The rule won't
        # compile; that's a model error to surface, not something to patch.
        logger.warning(f"YARA: condition references undeclared strings: {undefined}")

    if not declared or re.search(r"\bthem\b", condition_text):
        return yara_rule

    def referenced(name: str) -> bool:
        return name in explicit or any(name.startswith(w) for w in wildcards)

    unreferenced = [n for n in declared if not referenced(n)]
    if not unreferenced:
        return yara_rule

    new_strings, removed = strings_text, []
    for name in unreferenced:
        line = re.search(r"^[ \t]*\$" + re.escape(name) + r"\s*=.*(?:\n|$)", new_strings, re.MULTILINE)
        if not line:
            continue
        decl = line.group(0)
        # Leave multi-line hex/regex declarations alone rather than cut them in half.
        if decl.count("{") != decl.count("}"):
            continue
        new_strings = new_strings[:line.start()] + new_strings[line.end():]
        removed.append(f"${name}")

    if removed:
        logger.warning(f"YARA: removed unreferenced strings: {removed}")
        yara_rule = yara_rule[:sections.start(1)] + new_strings + yara_rule[sections.end(1):]
    return yara_rule


def parse_model_json(text: str) -> dict:
    """
    Parse the model's JSON answer. Tolerates a markdown fence or stray prose
    around a single top-level object. Raises ValueError otherwise.
    """
    clean = (text or "").strip()
    fence = re.match(r"^```[a-zA-Z0-9_-]*\s*\n(.*?)\n?```\s*$", clean, re.DOTALL)
    if fence:
        clean = fence.group(1).strip()
    try:
        obj = json.loads(clean)
    except json.JSONDecodeError:
        first, last = clean.find("{"), clean.rfind("}")
        if first == -1 or last <= first:
            raise ValueError("no JSON object found in model output") from None
        try:
            obj = json.loads(clean[first:last + 1])
        except json.JSONDecodeError as e:
            raise ValueError(f"model output is not valid JSON: {e}") from None
    if not isinstance(obj, dict):
        raise ValueError(f"model output is JSON {type(obj).__name__}, expected an object")
    return obj


def run_synthesis(
    analysis: dict,
    rendered,
    bundle_sha: str,
    bundle_path: Path,
    engine,
    cost_estimate: dict,
    analyst_notes: str = "",
    runs_dir: Path = None,
    mode: str = "prod",
) -> dict:
    """
    Run one synthesis and write its run directory. Returns the report-compatible
    result dict; result["error"] is set on any failure (the manifest is written
    either way, with status "error").
    """
    runs_dir = Path(runs_dir or mf.RUNS_DIR)
    started = mf.utc_now()
    run_id = mf.new_run_id(bundle_sha, engine.id, started)
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    logger.info(f"Run {run_id}: engine {engine.id}")
    er = engine.run(rendered.prompt)
    finished = mf.utc_now()

    raw_path = None
    if er.raw is not None:
        raw_path = mf.write_json_atomic(run_dir / "raw_response.json", er.raw)

    schema_id = schema_for_template(rendered.template_id)
    error = er.error
    synthesis = None
    parsed = None
    schema_report = None
    if error is None:
        try:
            parsed = parse_model_json(er.text)
        except ValueError as e:
            error = f"Failed to parse model response as JSON: {e}"
    if parsed is not None:
        synthesis, schema_report = validate_output(parsed, schema_id)
        if synthesis is None:
            n = len(schema_report["errors"])
            error = f"Output failed schema validation ({schema_id}): {n} error(s); see manifest"
    if synthesis is not None:
        yara_section = synthesis.get("yara_rule", {})
        if isinstance(yara_section, dict) and isinstance(yara_section.get("rule"), str):
            yara_section["rule"] = validate_yara_strings(yara_section["rule"])

    manifest_path = run_dir / "manifest.json"
    synthesis_path = run_dir / "synthesis.json" if synthesis is not None else None
    manifest = mf.build_manifest(
        run_id=run_id,
        mode=mode,
        status="error" if error else "ok",
        error=error,
        sample_sha256=analysis.get("sample", {}).get("sha256"),
        bundle={"sha256": bundle_sha, "path": mf.rel(bundle_path)},
        template={"id": rendered.template_id, "sha256": rendered.template_sha256},
        prompt_sha256=rendered.prompt_sha256,
        output_schema={"id": schema_id,
                       "sha256": schema_report["schema_sha256"] if schema_report else None,
                       "constrained_decoding": False},
        engine={"id": er.engine_id, "sdk": er.sdk},
        model={"requested": er.model_requested, "reported": er.model_reported},
        params=er.params,
        defaults_assumed=er.defaults_assumed,
        usage=er.usage,
        cost={"estimate": cost_estimate,
              "actual_usd": actual_cost(er.usage, er.model_requested) if er.usage else None},
        response={"id": er.response_id, "stop_reason": er.stop_reason},
        timing={"started_at": started.isoformat(), "finished_at": finished.isoformat(),
                "duration_ms": int((finished - started).total_seconds() * 1000)},
        raw_response_path=mf.rel(raw_path) if raw_path else None,
        validation={
            "parsed_json": parsed is not None,
            "schema_valid": bool(schema_report and schema_report["valid"]),
            "errors": schema_report["errors"] if schema_report else [],
            "normalized": schema_report["normalized"] if schema_report else [],
        },
        analyst_notes_present=bool(analyst_notes),
        pipeline=mf.pipeline_commit(),
        synthesis_path=mf.rel(synthesis_path) if synthesis_path else None,
    )

    result = {
        "schema_version": "1.0",
        "synthesized_at": finished.isoformat(),
        "model": er.model_reported or er.model_requested or engine.id,
        "dry_run": engine.id == "dry-run",
        "cost_estimate": cost_estimate,
        "sample": analysis.get("sample", {}),
        "synthesis": synthesis,
        "error": error,
        "raw_response": er.text,
        "bundle_sha256": bundle_sha,
        "template": {"id": rendered.template_id, "sha256": rendered.template_sha256},
        "prompt_sha256": rendered.prompt_sha256,
        "manifest": {"run_id": run_id, "path": mf.rel(manifest_path)},
    }
    if analyst_notes:
        result["analyst_notes"] = analyst_notes
    if schema_report and not schema_report["valid"]:
        result["validation_errors"] = schema_report["errors"]

    if synthesis_path is not None:
        # The run's own copy (raw text lives in raw_response.json).
        mf.write_json_atomic(synthesis_path, {k: v for k, v in result.items() if k != "raw_response"})
    mf.write_json_atomic(manifest_path, manifest)
    if error:
        logger.error(f"Run {run_id} failed: {error}")
    return result


def save_synthesis(synthesis: dict) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    sha256 = synthesis["sample"].get("sha256", "unknown")
    out_path = OUTPUT_DIR / f"{sha256}.synthesis.json"
    with open(out_path, "w") as f:
        json.dump(synthesis, f, indent=2)
    logger.info(f"Synthesis saved: {out_path}")
    return out_path
