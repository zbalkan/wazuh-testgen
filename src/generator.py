#!/usr/bin/env python3

import argparse
import logging
import os
import sys
from typing import Final

from internal.evtx import EvtxConverter
from internal.ini import IniConverter
from internal.rule import RuleConverter

APP_NAME: Final[str] = 'wazuh-testgen'
APP_VERSION: Final[str] = '0.3'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a tool help detection engineers generate Wazuh rule tests either derived from INI test files from Wazuh repository, Windows Event Log (EVTX) files, or Wazuh rule files."
ENCODING: Final[str] = "utf-8"


def get_root_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    elif __file__:
        return os.path.dirname(__file__)
    else:
        return './'


def main() -> None:
    """Main function to start the application."""
    logging.info(f"Starting {APP_NAME} {APP_VERSION}")
    logging.info(DESCRIPTION)

    parser = argparse.ArgumentParser(description="Generate Python unittest tests for Wazuh rules.")
    parser.add_argument('--debug', '-d', action='store_true', help="Enable debug logging.")

    subparsers = parser.add_subparsers(dest='command')
    ini_parser = subparsers.add_parser(
        'ini', help="Generate Python unittest tests from INI files.")
    ini_parser.add_argument('--input_dir', '-i', required=True,
                            help="Directory where input files are located.")
    ini_parser.add_argument('--output_dir', '-o', required=True,
                            help="Directory where the Python test files will be saved.")

    evtx_parser = subparsers.add_parser(
        'evtx', help="Generate Python unittest tests from EVTX files.")
    evtx_parser.add_argument('--scenario', '-s', required=True, help="Name for the tests to use for the generated tests.")
    evtx_parser.add_argument('--input_dir', '-i', required=True,
                             help="Directory where input files are located.")
    evtx_parser.add_argument('--output_dir', '-o', required=True,
                             help="Directory where the Python test files will be saved.")

    rule_parser = subparsers.add_parser(
        'rule', help="Generate Python unittest tests from Wazuh rule files.")
    rule_parser.add_argument('--input_dir', '-i', required=True,
                             help="Directory where input files are located.")
    rule_parser.add_argument('--output_dir', '-o', required=True,
                             help="Directory where the Python test files will be saved.")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    input_directory = args.input_dir
    output_directory = args.output_dir

    # Ensure the output directory exists
    os.makedirs(output_directory, exist_ok=True)

    # Process all files in the input directory
    if not os.path.exists(input_directory):
        print(f"Error: Input directory '{input_directory}' not found.")
        sys.exit(1)

    command = str(args.command)
    if command == 'ini':
        ini_converter = IniConverter()
        wazuh_test_inis = [f for f in os.listdir(
            input_directory) if f.endswith('.ini')]
        if len(wazuh_test_inis) == 0:
            raise FileNotFoundError(f"No INI files found in {input_directory}")
        for wazuh_test_ini in wazuh_test_inis:
            logging.info(f"Processing INI file: {wazuh_test_ini}")
            ini_file_path = os.path.join(input_directory, wazuh_test_ini)
            ini_converter.convert(ini_file_path, output_directory)

    elif command == 'evtx':
        evtx_converter = EvtxConverter()
        evtx_converter.convert(args.scenario, input_directory, output_directory)
    elif command == 'rule':
        rule_converter = RuleConverter()
        rule_converter.convert(input_directory, output_directory)
    else:
        print("Error: No valid command specified.")
        parser.print_help()


def exception_handler(exc_type, exc_value, exc_traceback) -> None:
    if logging.root.level == logging.DEBUG:
        logging.error("Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))
    else:
        logging.error(f"({exc_type.__name__}): {exc_value}")


def setup_logging() -> None:
    log_path = os.path.join(get_root_dir(), f'{APP_NAME}.log')
    logging.basicConfig(
        filename=os.path.join(log_path),
        encoding=ENCODING,
        format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.INFO
    )
    sys.excepthook = exception_handler


if __name__ == "__main__":
    try:
        setup_logging()

        logging.info('Starting')
        main()
        logging.info('Exiting.')
    except KeyboardInterrupt:
        print('Cancelled by user.')
        logging.info('Cancelled by user.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print('ERROR: ' + str(ex))
        exception_handler(type(ex), ex, ex.__traceback__)
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
