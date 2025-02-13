import os
import pathlib

from wazuhevtx.evtx2json import EvtxToJson


class EvtxConverter:

    def convert(self, test_class_name: str, input_directory: str, output_directory: str) -> None:
        """Converts an INI file to a Python unittest file."""

        test_functions = []
        converter = EvtxToJson()

        # Walk through all files and subdirectories
        for root, _, files in os.walk(input_directory):
            for filename in files:
                if filename.endswith(".evtx"):
                    file_path = pathlib.Path(root, filename)

                    # Generate relative path (excluding base directory)
                    rel_path = os.path.relpath(file_path, input_directory)
                    function_name = f"test_{self.sanitize(rel_path)}"

                    # Convert EVTX to JSON logs
                    json_logs: list[str] = list(converter.to_json(file_path))
                    formatted_logs = ''
                    for i, log in enumerate(json_logs):
                        if i == len(json_logs) - 1:
                            formatted_logs += f"            '{log}'"
                        else:
                            formatted_logs += f"            '{log}',\n"

                    # Create test function with placeholders for assertions
                    test_function = f"""
    def {function_name}(self):
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
        self.fail("Test not implemented yet. Define expected results.")"""
                    test_functions.append(test_function)

        # Generate test class
        test_class_code = f"""\
import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class {test_class_name}(unittest.TestCase):
{''.join(test_functions)}
"""

        # Define output file based on class name
        test_file_path = os.path.join(
            output_directory, f"test_{test_class_name.lower()}.py")

        # Write to test file
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(test_class_code)

        print(f"Unit test file '{test_file_path}' generated successfully!")

    def sanitize(self, text: str) -> str:
        return text.replace(' ', '_').replace('#', '').replace(':', '_').replace('/', '_').replace('-', '_').replace('___', '_').replace('__', '_').replace('.', '').replace(',', '').replace('(', '').replace(')', '').replace("'", '').replace('"', '').replace('=', '').replace('?', '').replace('!', '').replace(';', '').replace('&', '').replace('@', '').replace('$', '').replace('%', '').replace('^', '').replace('*', '').replace('+', '').replace('~', '').replace('`', '').replace('[', '').replace(']', '').replace('{', '').replace('}', '').replace('\\', '').replace('|', '').replace('<', '').replace('>', '').lower()
