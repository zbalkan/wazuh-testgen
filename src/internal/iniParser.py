from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class TestCase:
    header: str
    log: str
    condition: Literal["pass", "fail"]
    rule: str
    alert: int
    decoder: str

    def __str__(self) -> str:
        return (
            f"Test Case: {self.header}\n"
            f"Log: {self.log}\n"
            f"Condition: {self.condition}\n"
            f"Rule ID: {self.rule}\n"
            f"Alert level: {self.alert}\n"
            f"Decoder: {self.decoder}"
        )


class IniParser:

    def parse(self, path: str) -> list[TestCase]:
        sections = self.__split(path)
        test_cases: list[TestCase] = []
        for section in sections:
            lines = self.__read(section)
            if lines:
                test_cases.extend(lines)

        return test_cases

    def __read(self, lines: list[str]) -> list[TestCase] | None:
        header = lines[0].replace("[", "").replace("]", "").lower()
        logs: list[tuple[str, Literal["pass", "fail"]]] = []
        rule: str | None = None
        alert: int | None = None
        decoder: str | None = None

        pairs: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            try:
                delim = line.index("=")
            except ValueError as exc:
                raise ValueError(f"Invalid line: {line} under {header}.") from exc

            key = line[:delim].strip()
            value = line[delim + 1:].strip()
            pairs.append((key, value))

        if not pairs:
            return None

        for key, value in pairs:
            if key.startswith("log"):
                parts = key.split()
                if len(parts) < 3 or parts[2] not in {"pass", "fail"}:
                    raise ValueError(
                        f"Invalid log condition '{key}' under {header}. "
                        "Expected 'log <number> pass' or 'log <number> fail'."
                    )
                logs.append((value, parts[2]))  # type: ignore[arg-type]
            elif key.startswith("rule"):
                rule = value
            elif key.startswith("alert"):
                try:
                    alert = int(value)
                except ValueError as exc:
                    raise ValueError(
                        f"Invalid alert level '{value}' under {header}."
                    ) from exc
            elif key.startswith("decoder"):
                decoder = value

        if not logs:
            return None

        missing = [
            name
            for name, value in (
                ("rule", rule),
                ("alert", alert),
                ("decoder", decoder),
            )
            if value is None
        ]
        if missing:
            raise ValueError(
                f"Missing {', '.join(missing)} under {header}."
            )

        assert rule is not None
        assert alert is not None
        assert decoder is not None

        if len(logs) == 1:
            log, condition = logs[0]
            return [TestCase(header, log, condition, rule, alert, decoder)]

        return [
            TestCase(
                f"{header} - {index}",
                log,
                condition,
                rule,
                alert,
                decoder,
            )
            for index, (log, condition) in enumerate(logs, start=1)
        ]

    def __split(self, path: str) -> list[list[str]]:
        sections: list[list[str]] = []
        current_section: list[str] = []
        section_header_pattern = re.compile(r"^\[(.*?)\]$")

        with open(path, "r", encoding="utf-8") as infile:
            for line in infile:
                line = line.strip()

                if section_header_pattern.match(line):
                    if current_section:
                        sections.append(current_section)
                        current_section = []

                    current_section.append(line)
                elif current_section:
                    current_section.append(line)

            if current_section:
                sections.append(current_section)

        return sections
