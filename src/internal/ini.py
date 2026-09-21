#!/usr/bin/env python3

from __future__ import annotations

import os

from internal.iniParser import IniParser, TestCase
from internal.naming import identifier


def _python_log_literal(value: str) -> str:
    trailing_backslashes = len(value) - len(value.rstrip("\\"))
    if trailing_backslashes % 2:
        return repr(value)

    for delimiter in ("'''", '"""'):
        if delimiter not in value:
            return f"r{delimiter}{value}{delimiter}"

    return repr(value)


class IniConverter:

    header_template = """\
#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from {ini_file_name}
"""

    positive_test_template = """\
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
{parameters}
    ],
)
def test_rule_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is LogtestStatus.RuleMatch
    assert response.decoder == decoder
    assert response.rule_id == rule_id
    assert response.rule_level == rule_level


"""

    negative_test_template = """\
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
{parameters}
    ],
)
def test_rule_does_not_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is not LogtestStatus.Error
    assert (
        response.decoder,
        response.rule_id,
        response.rule_level,
    ) != (
        decoder,
        rule_id,
        rule_level,
    )


"""

    def convert(self, wazuh_ini_test: str, output_directory: str) -> None:
        """Convert a Wazuh INI regression-test file to native pytest tests."""

        parser = IniParser()
        test_cases = parser.parse(wazuh_ini_test)

        if not test_cases:
            print(f"No test cases found in {wazuh_ini_test}")
            return

        ini_base_name = os.path.splitext(
            os.path.basename(wazuh_ini_test)
        )[0].lower()
        sanitized = identifier(ini_base_name)
        test_file_name = os.path.join(
            output_directory,
            f"test_{sanitized}_rules.py",
        )

        positive = [case for case in test_cases if case.condition == "pass"]
        negative = [case for case in test_cases if case.condition == "fail"]

        generated = self.header_template.format(
            ini_file_name=os.path.basename(wazuh_ini_test)
        )

        if positive:
            generated += self.positive_test_template.format(
                parameters=self._render_positive_parameters(positive)
            )

        if negative:
            generated += self.negative_test_template.format(
                parameters=self._render_negative_parameters(negative)
            )

        with open(test_file_name, "w", encoding="utf-8") as test_file:
            test_file.write(generated)

        print(f"Test file {test_file_name} created successfully.")

    @staticmethod
    def _render_positive_parameters(test_cases: list[TestCase]) -> str:
        return "\n".join(
            (
                "        pytest.param(\n"
                f"            {_python_log_literal(case.log)},\n"
                f"            {case.decoder!r},\n"
                f"            {case.rule!r},\n"
                f"            {case.alert},\n"
                f"            id={identifier(case.header)!r},\n"
                "        ),"
            )
            for case in test_cases
        )

    @staticmethod
    def _render_negative_parameters(test_cases: list[TestCase]) -> str:
        return "\n".join(
            (
                "        pytest.param(\n"
                f"            {_python_log_literal(case.log)},\n"
                f"            {case.decoder!r},\n"
                f"            {case.rule!r},\n"
                f"            {case.alert},\n"
                f"            id={identifier(case.header)!r},\n"
                "        ),"
            )
            for case in test_cases
        )
