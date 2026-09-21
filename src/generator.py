#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Final

from internal.evtx import EvtxConverter
from internal.ini import IniConverter
from internal.rule import RuleConverter

APP_NAME: Final[str] = "wazuh-testgen"
APP_VERSION: Final[str] = "0.4"
DESCRIPTION: Final[str] = (
    f"{APP_NAME} ({APP_VERSION}) generates pytest-formatted Wazuh rule tests "
    "from Wazuh INI regression tests, Windows EVTX files, or Wazuh rule XML."
)
ENCODING: Final[str] = "utf-8"


def get_root_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    if __file__:
        return os.path.dirname(__file__)
    return "./"


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


def setup_logging() -> None:
    log_path = os.path.join(get_root_dir(), f"{APP_NAME}.log")
    logging.basicConfig(
        filename=log_path,
        encoding=ENCODING,
        format="%(asctime)s:%(name)s:%(levelname)s:%(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.INFO,
    )
    sys.excepthook = exception_handler


if __name__ == "__main__":
    try:
        setup_logging()

        logging.info("Starting")
        main()
        logging.info("Exiting.")
    except KeyboardInterrupt:
        print("Cancelled by user.")
        logging.info("Cancelled by user.")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print("ERROR: " + str(ex))
        exception_handler(type(ex), ex, ex.__traceback__)
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
