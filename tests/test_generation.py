from __future__ import annotations

import ast

from internal.evtx import EvtxConverter
from internal.ini import IniConverter
from internal.naming import identifier
from internal.rule import RuleConverter


def test_identifier_sanitizes_arbitrary_text() -> None:
    assert identifier("Su: failed / root") == "su_failed_root"
    assert identifier("123") == "case_123"
    assert identifier("", fallback="root") == "root"


def test_ini_converter_generates_native_pytest(tmp_path) -> None:
    source = tmp_path / "su.ini"
    output = tmp_path / "out"
    output.mkdir()

    source.write_text(
        """\
[SU failed]
log 1 pass = Apr 27 host su[123]: failed: user's ''' marker
rule = 5302
alert = 9
decoder = su

[SU negative]
log 1 fail = Apr 27 host su[124]: authentication failure
rule = 5503
alert = 5
decoder = su
""",
        encoding="utf-8",
    )

    IniConverter().convert(str(source), str(output))

    generated = (output / "test_su_rules.py").read_text(encoding="utf-8")
    ast.parse(generated)

    assert "import unittest" not in generated
    assert "import pytest" in generated
    assert "from wazuhtester import LogtestStatus, send_log" in generated
    assert "pytestmark = pytest.mark.wazuh_logtest" in generated
    assert "def test_rule_match(" in generated
    assert "def test_rule_does_not_match(" in generated
    assert "assert response.status is not LogtestStatus.Error" in generated


def test_rule_converter_generates_skipped_pytest_templates(tmp_path) -> None:
    source = tmp_path / "rules"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()

    (source / "example.xml").write_text(
        """\
<group name="example,">
  <rule id="100001" level="7">
    <description>Example detection</description>
    <groups>authentication_failed,</groups>
  </rule>
</group>
""",
        encoding="utf-8",
    )

    RuleConverter().convert(str(source), str(output))

    generated = (output / "test_example.py").read_text(encoding="utf-8")
    ast.parse(generated)

    assert "import unittest" not in generated
    assert "import pytest" in generated
    assert "@pytest.mark.skip" in generated
    assert "def test_rule_100001() -> None:" in generated
    assert "assert response.rule_id == '100001'" in generated
    assert "'authentication_failed' in response.rule_groups" in generated


class _FakeEvtxToJson:
    def to_json(self, _path):
        return iter(
            [
                '{"win":{"system":{"eventID":"1"}}}',
                '{"win":{"system":{"eventID":"3"}}}',
            ]
        )


def test_evtx_converter_generates_root_pytest_template(tmp_path) -> None:
    source = tmp_path / "evtx"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    (source / "scenario.evtx").write_bytes(b"placeholder")

    converter = object.__new__(EvtxConverter)
    converter.converter = _FakeEvtxToJson()
    converter.convert(str(source), str(output))

    generated = (output / "test_root.py").read_text(encoding="utf-8")
    ast.parse(generated)

    assert "import unittest" not in generated
    assert "import pytest" in generated
    assert "from wazuhtester import send_multiple_logs" in generated
    assert "@pytest.mark.skip(reason='Define expected detections for scenario.evtx')" in generated
    assert "def test_scenario() -> None:" in generated
    assert "T1021.001" not in generated
