from __future__ import annotations

import sys

import pytest

from wazuhtestgen import generator


def test_evtx_command_fails_before_creating_output_on_non_windows(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    source = tmp_path / "input"
    output = tmp_path / "output"
    source.mkdir()

    monkeypatch.setattr(generator.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "wazuh-testgen",
            "evtx",
            "--input_dir",
            str(source),
            "--output_dir",
            str(output),
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        generator.main()

    assert exc_info.value.code == 2
    stderr = capsys.readouterr().err
    assert "usage:" in stderr
    assert "Windows" in stderr
    assert not output.exists()


@pytest.mark.parametrize(
    ("system_name", "command"),
    [
        ("Linux", "ini"),
        ("Darwin", "ini"),
        ("Linux", "rule"),
        ("Darwin", "rule"),
    ],
)
def test_ini_and_rule_commands_run_on_non_windows(
    tmp_path,
    monkeypatch,
    system_name: str,
    command: str,
) -> None:
    source = tmp_path / "input"
    output = tmp_path / "output"
    source.mkdir()

    if command == "ini":
        (source / "example.ini").write_text(
            "[Example]\n"
            "log 1 pass = example log\n"
            "rule = 100001\n"
            "alert = 3\n"
            "decoder = test\n",
            encoding="utf-8",
        )
        expected = output / "test_example_rules.py"
    else:
        (source / "example.xml").write_text(
            '<rule id="100001" level="3"><description>Example</description></rule>',
            encoding="utf-8",
        )
        expected = output / "test_example.py"

    monkeypatch.setattr(generator.platform, "system", lambda: system_name)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "wazuh-testgen",
            command,
            "--input_dir",
            str(source),
            "--output_dir",
            str(output),
        ],
    )

    generator.main()

    assert expected.is_file()


def test_run_maps_unexpected_exception_to_exit_code_one(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(generator, "setup_logging", lambda: None)

    def fail() -> None:
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(generator, "main", fail)

    with pytest.raises(SystemExit) as exc_info:
        generator.run()

    assert exc_info.value.code == 1
    assert "ERROR: unexpected failure" in capsys.readouterr().err
