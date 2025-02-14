import logging
import os
import pathlib

from wazuhevtx.evtx2json import EvtxToJson


class EvtxConverter:

    def convert(self, input_directory: str, output_directory: str) -> None:
        """Converts logs in EVTX to a Python unittest tests."""

        converter = EvtxToJson()

        # Walk through all files and subdirectories
        for root, _, files in os.walk(input_directory):
            evtx_files = [f for f in files if f.endswith(".evtx")]
            if not evtx_files:
                continue
            # Generate class name based on subdirectories
            subdirs = pathlib.Path(root).relative_to(input_directory).parts
            sanitized_class_name = self.sanitize(
                "_".join(subdirs)) if subdirs else "root"
            test_class_name = self.snake_to_pascal(sanitized_class_name)

            logging.info(f"Generating test class: {test_class_name}")

            test_functions = []

            for filename in evtx_files:
                file_path = pathlib.Path(root, filename)
                logging.info(f"Processing EVTX file: {file_path}")

                function_name = f"test_{self.sanitize(file_path.stem)}"

                # Convert EVTX to JSON logs
                json_logs: list[str] = list(converter.to_json(file_path))
                formatted_logs = ''
                for i, log in enumerate(json_logs):
                    if i == len(json_logs) - 1:
                        formatted_logs += f"            r'''{log}'''"
                    else:
                        formatted_logs += f"            r'''{log}''',\n"

                # Create test function with placeholders for assertions
                test_function = f"""
    def {function_name}(self) -> None:
        # Logs extracted from EVTX file
        logs = [
{formatted_logs}
        ]

        responses = send_multiple_logs(logs, location="stdin", log_format="json")

        # Ensure we receive a response for each log sent
        self.assertEqual(len(responses), len(logs))

        for _, response in enumerate(responses):
            self.assertEqual(response.status, LogtestStatus.RuleMatch)
            self.assertEqual(response.decoder, 'json')

            # Example: Set expected Wazuh rule ID and level when analyzing logs
            # expected_rule_id = None  # Replace with actual rule ID
            # expected_rule_level = None  # Replace with actual rule level

            # self.assertEqual(response.rule_id, expected_rule_id)
            # self.assertEqual(response.rule_level, expected_rule_level)

        # TODO: Write the expected result as test cases when the logs are analyzed by Wazuh.
        self.fail("Test not implemented yet. Define expected results.")
"""
                test_functions.append(test_function)

            # Generate test class
            test_class_code = f"""\
import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class Test{test_class_name}(unittest.TestCase):
{''.join(test_functions)}"""

            # Define output file per directory
            test_file_path = os.path.join(
                output_directory, f"test_{self.sanitize('_'.join(subdirs)).lower()}.py")

            # Write to test file
            with open(test_file_path, "w", encoding="utf-8") as f:
                f.write(test_class_code)

            print(f"Unit test file '{test_file_path}' generated successfully!")

    def sanitize(self, text: str) -> str:
        return text.replace('.evtx', '').replace('\\', '_').replace(' ', '_').replace('#', '').replace(':', '_').replace('/', '_').replace('-', '_').replace('___', '_').replace('__', '_').replace('.', '').replace(',', '').replace('(', '').replace(')', '').replace("'", '').replace('"', '').replace('=', '').replace('?', '').replace('!', '').replace(';', '').replace('&', '').replace('@', '').replace('$', '').replace('%', '').replace('^', '').replace('*', '').replace('+', '').replace('~', '').replace('`', '').replace('[', '').replace(']', '').replace('{', '').replace('}', '').replace('\\', '').replace('|', '').replace('<', '').replace('>', '').lower()

    def snake_to_pascal(self, snake_str: str) -> str:
        return ''.join(word.capitalize() for word in snake_str.split('_'))
