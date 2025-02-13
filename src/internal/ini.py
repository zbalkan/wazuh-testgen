#!/usr/bin/env python3

import os

from internal.parser import TestParser


class IniConverter:

    # Class template for the test file header
    class_template = '''\
#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from {ini_file_name}
class Test{class_name}Rules(unittest.TestCase):
'''

    # Test method template for each log entry
    test_method_template_pass = """\

    def test_{section}(self) -> None:
        log = r'''
{log_content}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, '{decoder}')
        self.assertEqual(response.rule_id, '{rule}')
        self.assertEqual(response.rule_level, {alert})

"""

    test_method_template_fail = """\

    def test_{section}(self) -> None:
        log = r'''
{log_content}
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '{rule}')

"""

    def convert(self, wazuh_ini_test: str, output_directory: str) -> None:
        """Converts an INI file to a Python unittest file."""

        parser = TestParser()
        test_cases = parser.parse(wazuh_ini_test)

        if len(test_cases) == 0:
            print(f"No test cases found in {wazuh_ini_test}")
            return

        ini_base_name = os.path.splitext(
            os.path.basename(wazuh_ini_test))[0].lower()

        sanitized = self.sanitize(ini_base_name)
        class_name = self.snake_to_pascal(sanitized)

        test_file_name = os.path.join(
            output_directory, f"test_{sanitized}_rules.py")

        with open(test_file_name, 'w') as test_file:
            test_file.write(self.class_template.format(
                class_name=class_name, ini_file_name=os.path.basename(wazuh_ini_test)))

            for test_case in test_cases:
                test_function: str = self.test_method_template_pass if test_case.condition == 'pass' else self.test_method_template_fail

                test_file.write(test_function.format(
                                section=self.sanitize(test_case.header),
                                log_content=test_case.log,
                                decoder=test_case.decoder,
                                rule=test_case.rule,
                                alert=test_case.alert))

        print(f"Test file {test_file_name} created successfully.")

    def sanitize(self, text: str) -> str:
        return text.replace(' ', '_').replace('#', '').replace(':', '_').replace('/', '_').replace('-', '_').replace('___', '_').replace('__', '_').replace('.', '').replace(',', '').replace('(', '').replace(')', '').replace("'", '').replace('"', '').replace('=', '').replace('?', '').replace('!', '').replace(';', '').replace('&', '').replace('@', '').replace('$', '').replace('%', '').replace('^', '').replace('*', '').replace('+', '').replace('~', '').replace('`', '').replace('[', '').replace(']', '').replace('{', '').replace('}', '').replace('\\', '').replace('|', '').replace('<', '').replace('>', '').lower()

    def snake_to_pascal(self, snake_str: str) -> str:
        return ''.join(word.capitalize() for word in snake_str.split('_'))
