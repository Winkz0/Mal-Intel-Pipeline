"""
bundle.py
M13 v2 (D2.1): the synthesis input bundle.

A bundle is exactly what the model sees, separated from how it is phrased:
sample metadata, the static-analysis fields the prompt uses (already capped),
IOC candidates and analyst notes, plus the caps applied and what they cut.
Templates (prompt_builder.render) turn a bundle into prompt text; the benchmark
perturbs bundles, so production code never forks.

Identity: the bundle ID is the SHA-256 of its canonical JSON (sorted keys,
compact separators, ASCII-only escapes). save_bundle() writes those exact
bytes, so `sha256sum <id>.json` equals the file name.

Field values are resolved with the same defaults the pre-v2 prompt builder used
(e.g. a missing packer becomes "none detected"), so the v1 template can reproduce
the legacy prompt byte for byte.
"""

import copy
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path

BUNDLE_VERSION = 1

# Caps that reproduce the pre-v2 prompt exactly (f-string slices in the old
# prompt_builder). Used for template parity checks, not production.
LEGACY_CAPS = {
    "notable_strings": 50,
    "capabilities": 30,
    "suspicious_imports": 30,
    "ioc_per_type": 20,
    "max_str_len": None,
}

# Production caps: legacy slices plus the 256-char per-string limit that the
# old token-limit fallback applied only after a failed API call.
DEFAULT_CAPS = {**LEGACY_CAPS, "max_str_len": 256}

TRUNCATION_MARKER = "... [TRUNCATED]"

_CAP_KEYS = frozenset(LEGACY_CAPS)


class BundleError(ValueError):
    """The analysis can't be turned into a valid bundle."""


# ── canonical form ──────────────────────────────────────────────────────────

def canonical_bytes(obj) -> bytes:
    """Deterministic serialization used for hashing and storage."""
    try:
        text = json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as e:
        raise BundleError(f"bundle is not canonical-JSON serializable: {e}") from e
    return text.encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bundle_id(bundle: dict) -> str:
    return sha256_hex(canonical_bytes(bundle))


# ── helpers ─────────────────────────────────────────────────────────────────

def _section(parent: dict, key: str) -> dict:
    value = parent.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise BundleError(f"'{key}' must be an object, got {type(value).__name__}")
    return value


def _as_list(value, name: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise BundleError(f"'{name}' must be a list, got {type(value).__name__}")
    return value


def _cap(items: list, limit, name: str, truncation: dict) -> list:
    kept = items if limit is None else items[:limit]
    truncation[name] = {"total": len(items), "kept": len(kept)}
    return list(kept)


def _shorten(items: list, max_len, name: str, truncation: dict) -> list:
    if max_len is None:
        return items
    out, shortened = [], 0
    for s in items:
        if isinstance(s, str) and len(s) > max_len:
            out.append(s[:max_len] + TRUNCATION_MARKER)
            shortened += 1
        else:
            out.append(s)
    truncation[name]["shortened"] = shortened
    return out


def _check_caps(caps: dict) -> dict:
    if set(caps) != _CAP_KEYS:
        raise BundleError(f"caps must have exactly these keys: {sorted(_CAP_KEYS)}")
    for k, v in caps.items():
        if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 1):
            raise BundleError(f"cap '{k}' must be a positive int or None")
    return dict(caps)


def _reject_non_finite(obj, path="analysis"):
    # json.load accepts NaN/Infinity; canonical JSON doesn't. Fail with a path.
    if isinstance(obj, float) and not math.isfinite(obj):
        raise BundleError(f"non-finite number at {path}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _reject_non_finite(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _reject_non_finite(v, f"{path}[{i}]")


# ── build ───────────────────────────────────────────────────────────────────

def build_bundle(analysis: dict, caps: dict = None, analyst_notes: str = "") -> dict:
    """
    Assemble the model-input bundle from a normalized analysis document.
    The analysis dict is not modified.
    """
    if not isinstance(analysis, dict):
        raise BundleError("analysis must be an object")
    caps = _check_caps(DEFAULT_CAPS if caps is None else caps)
    if analyst_notes is None:
        analyst_notes = ""
    if not isinstance(analyst_notes, str):
        raise BundleError("analyst_notes must be a string")

    _reject_non_finite(analysis)
    analysis_hash = sha256_hex(canonical_bytes(analysis))
    a = copy.deepcopy(analysis)

    sample = _section(a, "sample")
    static = _section(a, "static_analysis")
    iocs = _section(a, "ioc_candidates")
    diec = _section(static, "diec")
    pe = _section(static, "pefile")
    floss = _section(static, "floss")
    capa = _section(static, "capa")

    truncation = {}

    notable = _cap(_as_list(floss.get("notable_strings", []), "floss.notable_strings"),
                   caps["notable_strings"], "notable_strings", truncation)
    notable = _shorten(notable, caps["max_str_len"], "notable_strings", truncation)

    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "source": {"analysis_sha256": analysis_hash},
        "caps": caps,
        "sample": {
            "sha256": sample.get("sha256", "unknown"),
            "file_name": sample.get("file_name", "unknown"),
            "file_type": sample.get("file_type", "unknown"),
            "malware_family": sample.get("malware_family", "unknown"),
            "tags": _as_list(sample.get("tags", []), "sample.tags"),
        },
        "diec": {
            "file_type": diec.get("file_type") or "unknown",
            "compiler": diec.get("compiler") or "unknown",
            "packer": diec.get("packer") or "none detected",
            "is_packed": diec.get("is_packed", False),
        },
        "pefile": {
            "architecture": pe.get("architecture") or "unknown",
            "compile_timestamp": pe.get("compile_timestamp") or "unknown",
            "imphash": pe.get("imphash") or "n/a",
            "suspicious_imports": _cap(
                _as_list(pe.get("suspicious_imports", []), "pefile.suspicious_imports"),
                caps["suspicious_imports"], "suspicious_imports", truncation),
            "high_entropy_sections": _as_list(
                pe.get("high_entropy_sections", []), "pefile.high_entropy_sections"),
        },
        "floss": {
            "total_static": floss.get("total_static", 0),
            "total_decoded": floss.get("total_decoded", 0),
            "notable_strings": notable,
        },
        "capa": {
            "capabilities": _cap(
                _as_list(capa.get("capabilities", []), "capa.capabilities"),
                caps["capabilities"], "capabilities", truncation),
            "attack_ttps": _as_list(capa.get("attack_ttps", []), "capa.attack_ttps"),
            "mbc_behaviors": _as_list(capa.get("mbc_behaviors", []), "capa.mbc_behaviors"),
        },
        "iocs": {
            t: _cap(_as_list(iocs.get(t, []), f"ioc_candidates.{t}"),
                    caps["ioc_per_type"], f"iocs.{t}", truncation)
            for t in ("ips", "urls", "commands")
        },
        "analyst_notes": analyst_notes,
        "truncation": truncation,
    }

    for ttp in bundle["capa"]["attack_ttps"]:
        if not isinstance(ttp, dict):
            raise BundleError("capa.attack_ttps entries must be objects")
    for b in bundle["capa"]["mbc_behaviors"]:
        if not isinstance(b, dict):
            raise BundleError("capa.mbc_behaviors entries must be objects")

    canonical_bytes(bundle)  # fail early if anything isn't serializable
    return bundle


# ── storage ─────────────────────────────────────────────────────────────────

def save_bundle(bundle: dict, bundle_dir: Path) -> tuple[str, Path]:
    """
    Write the bundle's canonical bytes to <bundle_dir>/<id>.json (atomic,
    content-addressed). Re-saving an identical bundle is a no-op.
    """
    data = canonical_bytes(bundle)
    bid = sha256_hex(data)
    bundle_dir = Path(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    path = bundle_dir / f"{bid}.json"

    if path.exists():
        if path.read_bytes() != data:
            raise BundleError(f"existing bundle file does not match its ID: {path}")
        return bid, path

    fd, tmp = tempfile.mkstemp(dir=bundle_dir, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return bid, path


def load_bundle(path: Path) -> dict:
    """Load a stored bundle and verify its bytes hash to its file name."""
    path = Path(path)
    data = path.read_bytes()
    expected = path.stem
    actual = sha256_hex(data)
    if actual != expected:
        raise BundleError(f"bundle hash mismatch: {path.name} hashes to {actual}")
    bundle = json.loads(data)
    if canonical_bytes(bundle) != data:
        raise BundleError(f"bundle file is not in canonical form: {path.name}")
    return bundle
