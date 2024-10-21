import re
from typing import Any


class TestCase:
    header: str
    log:str
    condition:str
    rule:str
    alert:str
    decoder:str

    def __init__(self, header:str, log:str,condition:str,rule:str,alert:str,decoder:str) -> None:
        self.header = header
        self.log = log
        self.condition = condition
        self.rule = rule
        self.alert = alert
        self.decoder = decoder

    def __str__(self) -> str:
        return f'Test Case: {self.header}\nLog: {self.log}\nCondition: {self.condition}\nRule ID: {self.rule}\nAlert level: {self.alert}\nDecoder: {self.decoder}'



class TestParser:

    def parse(self, path:str) -> list[TestCase]:
        section = self.__split(path)
        test_cases: list[TestCase] = []
        for section in section:
            test_cases.extend(self.read(section))

        return test_cases


    def read(self, lines:list[str]) -> list[TestCase]:

        header: str = lines[0].replace('[', '').replace(']', '')
        logs:list[tuple] = []
        rule:str
        alert:str
        decoder:str
        condition:str

        result:list[TestCase] = []

        pairs: list[tuple[str,Any]] = []
        for line in lines[1:]:
            if not line or line.startswith('#') or line.startswith(';') or line == '':
                continue
            try:
                delim = line.index('=')
            except:
                print('')
            k = line[0:delim].strip()
            v = line[delim+1:].strip()
            pairs.append((k,v))

        for k,v in pairs:
            if (k.startswith('log')):
                condition = k.split(' ')[2]
                logs.append((v, condition))

            if (k.startswith('rule')):
                rule = str(v)
            if (k.startswith('alert')):
                alert = str(v)
            if (k.startswith('decoder')):
                decoder = v

        if len(logs) == 1:
            result.append(TestCase(header,logs[0][0],logs[0][1],rule,alert,decoder))
            return result
        else:
            for i, t in enumerate(logs):
                result.append(TestCase(header + ' - ' + str(i + 1),
                            t[0], t[1], rule, alert, decoder))

        return result


    def __split(self, path:str) -> list[list[str]]:
        sections: list[list[str]] = []  # List to hold each section as a block
        current_section: list[str] = []  # List to hold lines of the current section
        # Pattern to match section headers
        section_header_pattern = re.compile(r'^\[(.*?)\]$')

        with open(path, 'r') as infile:
            for line in infile:
                line = line.strip()

                # Match a section header
                section_match = section_header_pattern.match(line)
                if section_match:
                    # If we encounter a new section header, save the current section if it's not empty
                    if current_section:
                        sections.append(current_section)
                        current_section = []  # Reset for the new section

                    # Start a new section with the header
                    current_section.append(line)
                else:
                    # Add the key-value pair to the current section
                    if current_section:
                        current_section.append(line)

            # Append the last section
            if current_section:
                sections.append(current_section)

        return sections
