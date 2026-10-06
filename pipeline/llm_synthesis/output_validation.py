"""
output_validation.py
M13 v2 (D2.3): validate model output against the JSON Schema for its template,
before anything is written to output/reports.

Applies to every engine (API, Desktop inbox, local): engines can't be trusted to
constrain their own output, and Desktop/local can't constrain decoding at all.

Normalization before validation (recorded in the result, never silent):
- enum values (verdict.classification, every *.confidence) are lower-cased and
  stripped; the API's own structured-output mode doesn't guarantee case either
- ATT&CK technique IDs are stripped and upper-cased ("t1055" -> "T1055")
"""

import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"

TEMPLATE_SCHEMAS = {
    "synthesis_v1": "synthesis_output.v1",
    "synthesis_v2": "synthesis_output.v2",
}

MAX_ERRORS = 50

_CONFIDENCE_PATHS = (("verdict",), ("ttp_mapping",), ("yara_rule",), ("sigma_rule",))


class SchemaError(ValueError):
    pass


def schema_for_template(template_id: str) -> str:
    try:
        return TEMPLATE_SCHEMAS[template_id]
    except KeyError:
        raise SchemaError(f"no output schema mapped for template {template_id}") from None


def load_schema(schema_id: str) -> tuple[dict, str]:
    """Return (schema, sha256_of_file_bytes)."""
    path = SCHEMA_DIR / f"{schema_id}.json"
    if not path.exists():
        raise SchemaError(f"unknown output schema: {schema_id}")
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def normalize(output: dict) -> tuple[dict, list[str]]:
    """Case-normalize enums and technique IDs. Returns (copy, paths_changed)."""
    out = copy.deepcopy(output)
    changed = []

    def fix_enum(obj, key, path):
        v = obj.get(key) if isinstance(obj, dict) else None
        if isinstance(v, str):
            n = v.strip().lower()
            if n != v:
                obj[key] = n
                changed.append(path)

    for (section,) in _CONFIDENCE_PATHS:
        fix_enum(out.get(section), "confidence", f"{section}.confidence")
    fix_enum(out.get("verdict"), "classification", "verdict.classification")

    techniques = (out.get("ttp_mapping") or {}).get("techniques") if isinstance(out.get("ttp_mapping"), dict) else None
    if isinstance(techniques, list):
        for i, t in enumerate(techniques):
            if isinstance(t, dict) and isinstance(t.get("id"), str):
                n = t["id"].strip().upper()
                if n != t["id"]:
                    t["id"] = n
                    changed.append(f"ttp_mapping.techniques[{i}].id")
    return out, changed


def _path(err) -> str:
    parts = []
    for p in err.absolute_path:
        parts.append(f"[{p}]" if isinstance(p, int) else (f".{p}" if parts else str(p)))
    return "".join(parts) or "(root)"


def validate_output(output, schema_id: str) -> tuple[dict | None, dict]:
    """
    Normalize and validate. Returns (normalized_output_or_None, report) where
    report = {schema_id, schema_sha256, valid, errors, normalized}. The output
    is None when it doesn't validate.
    """
    schema, schema_sha = load_schema(schema_id)
    report = {"schema_id": schema_id, "schema_sha256": schema_sha,
              "valid": False, "errors": [], "normalized": []}
    if not isinstance(output, dict):
        report["errors"] = [f"(root): expected an object, got {type(output).__name__}"]
        return None, report

    normalized, changed = normalize(output)
    report["normalized"] = changed
    errors = sorted(Draft202012Validator(schema).iter_errors(normalized),
                    key=lambda e: (list(map(str, e.absolute_path)), e.message))
    report["errors"] = [f"{_path(e)}: {e.message}"[:300] for e in errors[:MAX_ERRORS]]
    if len(errors) > MAX_ERRORS:
        report["errors"].append(f"... {len(errors) - MAX_ERRORS} more")
    report["valid"] = not errors
    return (normalized if not errors else None), report
