import logging
import os
import pathlib
import platform


class EvtxConverter:

    def __init__(self) -> None:
        if platform.system() != "Windows":
            raise Exception("Error: EVTX parsing works only on Windows platforms.")
        try:
            from wazuhevtx.evtx2json import EvtxToJson
            self.converter = EvtxToJson()
        except ImportError:
            raise Exception("Error: You cannot use this command if you don't have wazuhevtx package.")

    def convert(self, test_class_name: str, input_directory: str, output_directory: str) -> None:
        """Converts an EVTX file to a Python unittest file."""

        test_functions = []

        # Sanitize test class name
        test_class_name = self.__snake_to_pascal(self.__sanitize(test_class_name))
        logging.info(f"Generating unit test class: {test_class_name}")

        # Walk through all files and subdirectories
        for root, _, files in os.walk(input_directory):
            for filename in [f for f in files if f.endswith(".evtx")]:
                file_path = pathlib.Path(root, filename)

                # Generate relative path (excluding base directory)
                rel_path = str(file_path.relative_to(input_directory))
                logging.info(f"Processing EVTX file: {rel_path}")

                function_name = f"test_{self.__sanitize(rel_path)}"

                # Convert EVTX to JSON logs
                json_logs: list[str] = list(self.converter.to_json(file_path))
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
        logs: list[str] = [
{formatted_logs}
        ]

        responses: list[LogtestResponse] = send_multiple_logs(
            logs, log_format="json")

        # Ensure we receive a response for each log sent
        self.assertEqual(len(responses), len(logs))

        # If you want to check every log, simply use a for loop
        # for _, response in enumerate(responses):
        #     self.assertEqual(response.status, LogtestStatus.RuleMatch)
        #     self.assertEqual(response.decoder, 'json')

        #     Example: Set expected Wazuh rule ID and level when analyzing logs
        #     expected_rule_id = None  # Replace with actual rule ID
        #     expected_rule_level = None  # Replace with actual rule level

        #     self.assertEqual(response.rule_id, expected_rule_id)
        #       self.assertEqual(response.rule_level, expected_rule_level)

        # If you want a simple result after a series of logs, you can use an "at least one" control. For instance:

        # Ensure there is at least one alert gets triggered with T1021.001 - Remote Services: Remote Desktop Protocol
        expected_mitre_id: set[str] = {{'T1021.001'}}
        self.assertTrue(expr=any(expected_mitre_id & r.rule_mitre_ids for r in responses if r.rule_mitre_ids),
                        msg='T1021.001 not found in MITRE ATT&CK IDs')

        # TODO: Write the expected result as test cases when the logs are analyzed by Wazuh.
        self.fail("Test not implemented yet. Define expected results.")
"""
                test_functions.append(test_function)

        # Generate test class
        test_class_code = f"""\
import unittest

from internal.logtest import LogtestResponse, LogtestStatus, send_multiple_logs  # type: ignore


class Test{test_class_name}(unittest.TestCase):
{''.join(test_functions)}"""

        # Define output file based on class name
        test_file_path = os.path.join(
            output_directory, f"test_{test_class_name.lower()}.py")

        # Write to test file
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(test_class_code)

        print(f"Unit test file '{test_file_path}' generated successfully!")

    def __sanitize(self, text: str) -> str:
        return text.replace('.evtx', '').replace('\\', '_').replace(' ', '_').replace('#', '').replace(':', '_').replace('/', '_').replace('-', '_').replace('___', '_').replace('__', '_').replace(',', '_').replace('.', '').replace('(', '').replace(')', '').replace("'", '').replace('"', '').replace('=', '').replace('?', '').replace('!', '').replace(';', '').replace('&', '').replace('@', '').replace('$', '').replace('%', '').replace('^', '').replace('*', '').replace('+', '').replace('~', '').replace('`', '').replace('[', '').replace(']', '').replace('{', '').replace('}', '').replace('\\', '').replace('|', '').replace('<', '').replace('>', '').lower()

    def __snake_to_pascal(self, snake_str: str) -> str:
        return ''.join(word.capitalize() for word in snake_str.split('_'))
