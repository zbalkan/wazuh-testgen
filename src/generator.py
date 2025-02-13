#!/usr/bin/env python3

import argparse
import configparser
import logging
import os
import sys
from typing import Final

from internal.evtx import EvtxConverter
from internal.ini import IniConverter

APP_NAME: Final[str] = 'wazuh_test_generator'
APP_VERSION: Final[str] = '0.2'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a CLI tool to generate Wazuh rule tests from original INI files or EVTX files to Python's `unittest` tests. It is designed to accompany `wazuh-devenv` project."
ENCODING: Final[str] = "utf-8"


def load_config_file(config_file_path: str) -> tuple[str, str]:
    """Loads configuration from an INI file."""
    config = configparser.ConfigParser()
    config.read(os.path.abspath(config_file_path))

    if not config.has_section('settings'):
        raise ValueError(
            f"The configuration file '{config_file_path}' does not contain the 'settings' section.")

    input_directory = os.path.abspath(config.get(
        'settings', 'input_directory', fallback='./input'))
    output_directory = os.path.abspath(config.get(
        'settings', 'output_directory', fallback='./output'))
    return input_directory, output_directory


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

    subparsers = parser.add_subparsers(dest='command')
    ini_parser = subparsers.add_parser('ini', help="Generate Python unittest tests from INI files.")
    ini_parser.add_argument(
        '--config_file', '-c', help="Path to the configuration INI file.")
    ini_parser.add_argument('--input_directory', '-i', help="Directory where input files are located.")
    ini_parser.add_argument('--output_directory', '-o', help="Directory where the Python test files will be saved.")

    evtx_parser = subparsers.add_parser(
        'evtx', help="Generate Python unittest tests from EVTX files.")
    evtx_parser.add_argument('--scenario', '-s', required=True, help="Name for the tests to use for the generated tests.")
    evtx_parser.add_argument(
        '--config_file', '-c', help="Path to the configuration INI file.")
    evtx_parser.add_argument('--input_directory', '-i', help="Directory where input files are located.")
    evtx_parser.add_argument('--output_directory', '-o', help="Directory where the Python test files will be saved.")

    args = parser.parse_args()

    # If input_directory or output_directory are not provided, load from config file
    if args.input_directory and args.output_directory:
        input_directory = args.input_directory
        output_directory = args.output_directory
    else:
        # Fallback to config file if parameters are not provided
        conf = args.config_file
        if conf == 'config.ini':
            conf = os.path.join(get_root_dir(), 'config.ini')

        if not os.path.exists(conf):
            raise Exception(f"Configuration file '{conf}' not found.")

        input_directory, output_directory = load_config_file(conf)

    # Ensure the output directory exists
    os.makedirs(output_directory, exist_ok=True)

    # Process all INI files in the input directory
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
            # try:
            ini_converter.convert(ini_file_path, output_directory)
            # except Exception as ex:
            #     print(f"Error processing INI file: {wazuh_test_ini} - {ex}")
    elif command == 'evtx':
        evtx_converter = EvtxConverter()
        evtx_converter.convert(args.scenario, input_directory, output_directory)
    else:
        print("Error: No command specified.")
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
