"""
run_context.py
M13 v2 (D2.5): process-wide run mode and the side-effect guard.

Eval mode is set by `synthesize.py --eval <label>` (or the benchmark runner) via
the MALINTEL_EVAL environment variable, so child processes inherit it. In eval
mode every write that production state depends on raises SideEffectBlocked:
the pipeline DB, reports, rule files, STIX bundles, threat graph, RAG index,
validation reports and blog-post drafts. Eval output lives only under
output/eval/<label>/.

Belt and braces: the eval path also never imports pipeline.utils.db.
"""

import os
import re
from pathlib import Path

ENV_VAR = "MALINTEL_EVAL"
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class SideEffectBlocked(RuntimeError):
    """A production side effect was attempted in eval mode."""


def eval_label() -> str | None:
    return os.environ.get(ENV_VAR) or None


def is_eval() -> bool:
    return eval_label() is not None


def validate_label(label: str) -> str:
    if not isinstance(label, str) or not _LABEL.match(label) or ".." in label:
        raise ValueError("eval label must be 1-64 chars of A-Z a-z 0-9 . _ - and start alphanumeric")
    return label


def enter_eval(label: str) -> str:
    os.environ[ENV_VAR] = validate_label(label)
    return label


def eval_root(repo_root: Path, label: str = None) -> Path:
    label = validate_label(label or eval_label() or "")
    return Path(repo_root) / "output" / "eval" / label


def require_side_effects(action: str) -> None:
    """Call first in any function that writes production state."""
    label = eval_label()
    if label is not None:
        raise SideEffectBlocked(f"{action} is blocked in eval mode (label '{label}')")
