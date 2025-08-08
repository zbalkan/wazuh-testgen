# wazuh_test_generator

A tool to help detection engineers generate Wazuh rule tests either derived from INI test files from Wazuh repository, Windows Event Log (EVTX) files, or Wazuh rule files. The test format uses Python's `unittest`. It is designed to accompany `wazuh-devenv` project.

## Rationale

Wazuh uses an INI based rule testing solution. In order to get more flexibility, I used Python `unittest` package-based tests with `wazuh-devenv` project. This is a glue solution to convert INI files to Python unit test cases.

In time, I added EVTX capability thanks to another project of mine, [wazuhevtx](https://github.com/zbalkan/wazuhevtx). I generate test templates using the data in EVTX files so that detection engineers can make use of behavioral patterns based on attacks.

Finally, I added Wazuh rule to unit test converter for providing a template. The generated tests are not ready to use, but drafts to work on. You need to provide the log in the original format for proper testing.

## Usage

Top level (`generator.py --help`):

```plaintext
usage: generator.py [-h] [--debug] {ini,evtx,rule} ...

Generate Python unittest tests for Wazuh rules.

positional arguments:
  {ini,evtx,rule}
    ini            Generate Python unittest tests from INI files.
    evtx           Generate Python unittest tests from EVTX files.
    rule           Generate Python unittest tests from Wazuh rule files.

options:
  -h, --help       show this help message and exit
  --debug, -d      Enable debug logging.
```

INI parameters (`generator.py ini --help`):

```plaintext
usage: generator.py ini [-h] --input_dir INPUT_DIR --output_dir OUTPUT_DIR

options:
  -h, --help            show this help message and exit
  --input_dir, -i INPUT_DIR
                        Directory where input files are located.
  --output_dir, -o OUTPUT_DIR
                        Directory where the Python test files will be saved.
```

EVTX parameters (`generator.py evtx --help`):

```plaintext
usage: generator.py evtx [-h] --scenario SCENARIO --input_dir INPUT_DIR --output_dir OUTPUT_DIR

options:
  -h, --help            show this help message and exit
  --scenario, -s SCENARIO
                        Name for the tests to use for the generated tests.
  --input_dir, -i INPUT_DIR
                        Directory where input files are located.
  --output_dir, -o OUTPUT_DIR
                        Directory where the Python test files will be saved.
```

Wazuh rule parameters (`generator.py rule --help`):

```plaintext
usage: generator.py rule [-h] --input_dir INPUT_DIR --output_dir OUTPUT_DIR

options:
  -h, --help            show this help message and exit
  --input_dir, -i INPUT_DIR
                        Directory where input files are located.
  --output_dir, -o OUTPUT_DIR
                        Directory where the Python test files will be saved.
```

## Note

The `oscap.ini` file has a weird test case. The intention may have been to test a failure case, I am not sure. You need to fix that manually before running the INI converter.

The original case:

```ini
[OpenSCAP rule notapplicable]

oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", ...
```

Add `log 1 pass =` before the log:

```ini
[OpenSCAP rule notapplicable]

log 1 pass = oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", ...
```
