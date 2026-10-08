"""Required settings for scripts/remnux_revert.py: no homelab defaults in code."""

import importlib.util
import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "remnux_revert.py"


@pytest.fixture
def rr(monkeypatch):
    spec = importlib.util.spec_from_file_location("remnux_revert_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name, value in (("TOKEN_SECRET", "s"), ("API_URL", "https://pve.example:8006/api2/json"),
                        ("NODE", "node1"), ("VMID", "200")):
        monkeypatch.setattr(mod, name, value)
    return mod


def test_complete_settings_pass(rr):
    rr._require_settings()


@pytest.mark.parametrize("attr,env", [("TOKEN_SECRET", "PVE_TOKEN_SECRET"), ("API_URL", "PVE_API_URL"),
                                      ("NODE", "PVE_NODE"), ("VMID", "REMNUX_VMID")])
def test_each_required_setting_is_named_when_missing(rr, monkeypatch, attr, env):
    monkeypatch.setattr(rr, attr, "")
    with pytest.raises(rr.RevertError, match=env):
        rr._require_settings()


def test_context_checks_settings_before_anything_else(rr, monkeypatch):
    monkeypatch.setattr(rr, "API_URL", "")
    with pytest.raises(rr.RevertError, match="PVE_API_URL"):
        rr._context()


@pytest.mark.parametrize("attr,value,msg", [("API_URL", "http://pve.example:8006/api2/json", "https"),
                                            ("VMID", "210; rm", "number")])
def test_malformed_values_refused(rr, monkeypatch, attr, value, msg):
    monkeypatch.setattr(rr, attr, value)
    with pytest.raises(rr.RevertError, match=msg):
        rr._require_settings()


def test_no_homelab_defaults_in_source():
    src = SCRIPT.read_text(encoding="utf-8")
    for name in ("PVE_API_URL", "PVE_NODE", "REMNUX_VMID"):
        assert re.search(rf'getenv\("{name}", ""\)', src), f"{name} must default to empty"
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", src), "no IPv4 literals in the script"
