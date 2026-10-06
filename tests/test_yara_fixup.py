import pytest

from pipeline.llm_synthesis.synthesizer import validate_yara_strings

try:
    import yara
except ImportError:  # compile checks are skipped; text assertions still run
    yara = None


def compiles(rule: str) -> bool:
    if yara is None:
        return True
    try:
        yara.compile(source=rule)
        return True
    except yara.SyntaxError:
        return False


def R(strings: str, condition: str, meta: str = "") -> str:
    meta_block = f"  meta:\n{meta}" if meta else ""
    return f"rule t {{\n{meta_block}  strings:\n{strings}  condition:\n    {condition}\n}}"


def test_removes_only_unreferenced():
    rule = R('    $a = "alpha"\n    $b = "bravo"\n    $unused = "zulu"\n', "$a and $b")
    out = validate_yara_strings(rule)
    assert '$a = "alpha"' in out and '$b = "bravo"' in out and "$unused" not in out
    assert compiles(out)


def test_old_bug_regression_referenced_strings_survive():
    # Shape of the published Braodo rule: explicit refs mixed with wildcard sets.
    strings = "".join(f'    $py_lib{i} = "lib{i}"\n' for i in range(1, 6)) + (
        '    $crypto_kdf1 = "kdf"\n    $crypto_cipher = "aes"\n    $marker = "MRK"\n')
    cond = ("(4 of ($py_lib*)) or ($py_lib3 and $py_lib4 and 2 of ($crypto_*)) "
            "or ($marker and 3 of ($py_lib*)) or #py_lib1 > 5")
    rule = R(strings, cond)
    assert validate_yara_strings(rule) == rule
    assert compiles(rule)


@pytest.mark.parametrize("cond", ["any of them", "all of them", "2 of them"])
def test_them_keeps_everything(cond):
    rule = R('    $a = "a"\n    $b = "b"\n', cond)
    assert validate_yara_strings(rule) == rule


def test_wildcard_without_underscore_counts():
    rule = R('    $str1 = "a"\n    $str2 = "b"\n    $other = "c"\n', "all of ($str*)")
    out = validate_yara_strings(rule)
    assert "$str1" in out and "$str2" in out and "$other" not in out
    assert compiles(out)


@pytest.mark.parametrize("cond", ["#s1 > 2", "@s1[1] < 100", "!s1[1] == 3", "$s1 at 0"])
def test_count_offset_length_refs_count(cond):
    rule = R('    $s1 = "a"\n    $s10 = "b"\n', cond)
    out = validate_yara_strings(rule)
    assert '$s1 = "a"' in out and "$s10" not in out  # no prefix confusion


def test_meta_dollar_signs_ignored():
    rule = R('    $a = "a"\n', "$a", meta='    description = "costs $5 and $b"\n')
    assert validate_yara_strings(rule) == rule


def test_multiline_hex_left_alone():
    rule = R('    $a = "a"\n    $h = { 4D 5A\n           90 00 }\n', "$a")
    out = validate_yara_strings(rule)
    assert "{ 4D 5A" in out  # not cut in half


def test_undeclared_reference_is_logged_not_patched(caplog):
    rule = R('    $a = "a"\n', "$a and $ghost")
    assert validate_yara_strings(rule) == rule
    assert "undeclared" in caplog.text and "ghost" in caplog.text


@pytest.mark.parametrize("rule", ["", "[DRY RUN]", "rule t { condition: true }"])
def test_passthrough(rule):
    assert validate_yara_strings(rule) == rule
