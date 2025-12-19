#!/usr/bin/env python3

import logging
import os
import pathlib
import sys
import xml.etree.ElementTree as ET
from typing import Any, Final

ENCODING: Final[str] = "utf-8"
PLACEHOLDER_LOG: Final[str] = "TODO: provide a matching log here"


class RuleConverter:

    def convert(self, input_directory: str, output_directory: str) -> None:
        # Walk through all files and subdirectories
        for root, _, files in os.walk(input_directory):
            for filename in [f for f in files if f.endswith(".xml")]:
                file_path = pathlib.Path(root, filename)

                # Generate relative path (excluding base directory)
                rel_path = str(file_path.relative_to(input_directory))
                logging.info(f"Processing rule file: {rel_path}")

                test_class_name = self.__snake_to_pascal(
                    self.__sanitize(rel_path.replace('.xml', '')))

                rules = self.__collect_rules_from_file(file_path)
                test_class_code = self.__generate_unit_test_code(test_class_name, rules)

                # Define output file based on class name and file name
                test_file_path = os.path.join(
                    output_directory, f"test_{self.__sanitize(rel_path.replace('.xml', ''))}.py")

                # Write to test file
                with open(test_file_path, "w", encoding="utf-8") as f:
                    f.write(test_class_code)

                print(f"Unit test file '{test_file_path}' generated successfully!")

    def __collect_rules_from_file(self, rule_file: pathlib.Path) -> list[dict]:
        rules: list[dict[str, Any]] = []

        try:
            text = rule_file.read_text(encoding=ENCODING)
            root = ET.fromstring(f"<root>{text}</root>")

            def recurse(element: ET.Element, inherited: list[str]) -> None:
                # If this is a <group name="a,b,…">, extend inherited
                if element.tag == "group" and element.get("name"):
                    names = [g for g in element.get("name", "").split(",") if g]
                    inherited = inherited + names

                # If this is a <rule>, collect its data
                if element.tag == "rule":
                    rule_id = element.get("id")
                    level = element.get("level")
                    # Description (may be multiple <description> children)
                    descs = [d.text.strip() for d in element.findall("description") if d.text]
                    description = " ".join(descs) if descs else ""

                    # Start with any inherited groups
                    groups = list(inherited)

                    # Inline <groups>…</groups>
                    grp_el = element.find("groups")
                    if grp_el is not None and grp_el.text:
                        groups += [g.strip() for g in grp_el.text.split(",") if g.strip()]

                    rules.append({
                        "id": rule_id,
                        "level": level,
                        "description": description,
                        "groups": groups,
                    })

                # Recurse into all children, passing a copy of inherited
                for child in element:
                    recurse(child, inherited.copy())

            recurse(root, [])
        except Exception as e:
            print(
                f"[ERROR] Could not parse rule file {rule_file}: {e}", file=sys.stderr)

        return rules

    def __generate_unit_test_code(self, test_class_name: str, rules: list[dict]) -> str:
        lines = [
            "import unittest", "",
            "import internal.logtest as lt",
            "", "",
            "# TODO: Rename the class",
            f"class {test_class_name}(unittest.TestCase):",
            ""
        ]

        for rule in rules:
            rule_id = rule["id"]
            level = rule["level"]
            description = rule["description"].replace('"', '\\"')
            groups = rule["groups"]

            lines.append(f"    def test_rule_{rule_id}(self) -> None:")
            lines.append(f"        log = r'''{PLACEHOLDER_LOG}'''")
            lines.append("        response = lt.send_log(log)")
            lines.append("")
            lines.append(
                "        self.assertEqual(response.status, lt.LogtestStatus.RuleMatch)")
            lines.append(
                f"        self.assertEqual(response.rule_id, '{rule_id}')")
            lines.append(f"        self.assertEqual(response.rule_level, {level})")
            lines.append(
                f"        self.assertEqual(response.rule_description, \"{description}\")")
            for group in groups:
                lines.append(
                    f"        self.assertIn('{group}', response.rule_groups)  # type: ignore")
            lines.append("")

        return "\n".join(lines)

    def __sanitize(self, text: str) -> str:
        return text.replace('.evtx', '').replace('\\', '_').replace(' ', '_').replace('#', '').replace(':', '_').replace('/', '_').replace('-', '_').replace('___', '_').replace('__', '_').replace(',', '_').replace('.', '').replace('(', '').replace(')', '').replace("'", '').replace('"', '').replace('=', '').replace('?', '').replace('!', '').replace(';', '').replace('&', '').replace('@', '').replace('$', '').replace('%', '').replace('^', '').replace('*', '').replace('+', '').replace('~', '').replace('`', '').replace('[', '').replace(']', '').replace('{', '').replace('}', '').replace('\\', '').replace('|', '').replace('<', '').replace('>', '').lower()

    def __snake_to_pascal(self, snake_str: str) -> str:
        return ''.join(word.capitalize() for word in snake_str.split('_'))
