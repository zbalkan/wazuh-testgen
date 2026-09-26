#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import os
import platform
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Final

from .internal.evtx import EvtxConverter
from .internal.ini import IniConverter
from .internal.rule import RuleConverter

APP_NAME: Final[str] = "wazuh-testgen"
ENCODING: Final[str] = "utf-8"


def _package_version() -> str:
    try:
        return version(APP_NAME)
    except PackageNotFoundError:
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        in_project = False
        try:
            lines = pyproject.read_text(encoding=ENCODING).splitlines()
        except OSError as exc:
            raise RuntimeError(
                "Unable to determine the wazuh-testgen package version."
            ) from exc

        for raw_line in lines:
            line = raw_line.strip()
            if line == "[project]":
                in_project = True
                continue
            if line.startswith("[") and line.endswith("]"):
                in_project = False
                continue
            if in_project and line.startswith("version"):
                _, value = line.split("=", 1)
                return value.strip().strip('"').strip("'")

        raise RuntimeError(
            "Unable to determine the wazuh-testgen package version."
        )


APP_VERSION: Final[str] = _package_version()
DESCRIPTION: Final[str] = (
    f"{APP_NAME} ({APP_VERSION}) generates pytest-formatted Wazuh rule tests "
    "from Wazuh INI regression tests, Windows EVTX files, or Wazuh rule XML."
)


def main() -> None:
    """Run the command-line generator."""
    logging.info("Starting %s %s", APP_NAME, APP_VERSION)
    logging.info(DESCRIPTION)

    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Enable debug logging.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    ini_parser = subparsers.add_parser(
        "ini",
        help="Generate pytest tests from Wazuh INI regression tests.",
    )
    ini_parser.add_argument(
        "--input_dir",
        "-i",
        required=True,
        help="Directory where input files are located.",
    )
    ini_parser.add_argument(
        "--output_dir",
        "-o",
        required=True,
        help="Directory where generated Python tests will be saved.",
    )
    evtx_parser = subparsers.add_parser(
        "evtx",
        help="Generate editable pytest templates from EVTX files.",
    )
    evtx_parser.add_argument(
        "--input_dir",
        "-i",
        required=True,
        help="Directory where input files are located.",
    )
    evtx_parser.add_argument(
        "--output_dir",
        "-o",
        required=True,
        help="Directory where generated Python tests will be saved.",
    )

    rule_parser = subparsers.add_parser(
        "rule",
        help="Generate editable pytest templates from Wazuh rule XML files.",
    )
    rule_parser.add_argument(
        "--input_dir",
        "-i",
        required=True,
        help="Directory where input files are located.",
    )
    rule_parser.add_argument(
        "--output_dir",
        "-o",
        required=True,
        help="Directory where generated Python tests will be saved.",
    )

    args = parser.parse_args()

    if args.command == "evtx" and platform.system() != "Windows":
        parser.error(
            "the evtx command requires Windows, because wazuhevtx reads EVTX files "
            "through the Windows event log API. The ini and rule commands run on "
            "any operating system."
        )

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    input_directory = args.input_dir
    output_directory = args.output_dir

    if not os.path.exists(input_directory):
        print(f"Error: Input directory '{input_directory}' not found.")
        sys.exit(1)

    os.makedirs(output_directory, exist_ok=True)

    if args.command == "ini":
        ini_converter = IniConverter()
        wazuh_test_inis = [
            filename
            for filename in os.listdir(input_directory)
            if filename.endswith(".ini")
        ]
        if not wazuh_test_inis:
            raise FileNotFoundError(
                f"No INI files found in {input_directory}"
            )

        for wazuh_test_ini in wazuh_test_inis:
            logging.info("Processing INI file: %s", wazuh_test_ini)
            ini_file_path = os.path.join(
                input_directory,
                wazuh_test_ini,
            )
            ini_converter.convert(ini_file_path, output_directory)

    elif args.command == "evtx":
        EvtxConverter().convert(input_directory, output_directory)

    elif args.command == "rule":
        RuleConverter().convert(input_directory, output_directory)


def exception_handler(exc_type, exc_value, exc_traceback) -> None:
    if logging.root.level == logging.DEBUG:
        logging.error(
            "Unhandled exception",
            exc_info=(exc_type, exc_value, exc_traceback),
        )
    else:
        logging.error("(%s): %s", exc_type.__name__, exc_value)


def _log_directory() -> str:
    system = platform.system()

    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            base = os.path.join(os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, APP_NAME, "Logs")

    if system == "Darwin":
        return os.path.join(
            os.path.expanduser("~"),
            "Library",
            "Logs",
            APP_NAME,
        )

    base = os.environ.get("XDG_STATE_HOME")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, APP_NAME)


def setup_logging() -> None:
    log_directory = _log_directory()
    os.makedirs(log_directory, exist_ok=True)
    log_path = os.path.join(log_directory, f"{APP_NAME}.log")
    logging.basicConfig(
        filename=log_path,
        encoding=ENCODING,
        format="%(asctime)s:%(name)s:%(levelname)s:%(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.INFO,
    )
    sys.excepthook = exception_handler


def run() -> None:
    try:
        setup_logging()
        logging.info("Starting")
        main()
        logging.info("Exiting.")
    except KeyboardInterrupt:
        print("Cancelled by user.", file=sys.stderr)
        logging.info("Cancelled by user.")
        raise SystemExit(130)
    except Exception as ex:
        print(f"ERROR: {ex}", file=sys.stderr)
        exception_handler(type(ex), ex, ex.__traceback__)
        raise SystemExit(1)


if __name__ == "__main__":
    run()
