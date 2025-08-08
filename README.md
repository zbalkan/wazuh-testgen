# wazuh_test_generator

A tool to help detection engineers generate Wazuh rule tests either derived from INI files or Windows Event Log (EVTX) files. The test format uses Python's `unittest`. It is designed to accompany `wazuh-devenv` project.

## Rationale

Wazuh uses an INI based rule testing solution. In order to get more flexibility, I used Python `unittest` package-based tests with `wazuh-devenv` project. This is a glue solution to convert INI files to Python unit test cases.

In time, I added EVTX capability thanks to another project of mine, [wazuhevtx](https://github.com/zbalkan/wazuhevtx). I generate test templates using the data in EVTX files so that detection engineers can make use of behavioral patterns based on attacks.

## Usage

Top level (`generator.py --help`):

```plaintext
usage: generator.py [-h] {ini,evtx} ...

Generate Python unittest tests for Wazuh rules.

positional arguments:
  {ini,evtx}
    ini       Generate Python unittest tests from INI files.
    evtx      Generate Python unittest tests from EVTX files.

options:
  -h, --help  show this help message and exit
```

INI parameters (`generator.py ini --help`):

```plaintext
usage: generator.py ini [-h] [--config_file CONFIG_FILE] [--input_dir INPUT_DIRECTORY] [--output_dir OUTPUT_DIRECTORY]

options:
  -h, --help            show this help message and exit
  --config_file CONFIG_FILE, -c CONFIG_FILE
                        Path to the configuration INI file.
  --input_dir INPUT_DIRECTORY, -i INPUT_DIRECTORY
                        Directory where input files are located.
  --output_dir OUTPUT_DIRECTORY, -o OUTPUT_DIRECTORY
                        Directory where the Python test files will be saved.
```

EVTX parameters (`generator.py evtx --help`):

```plaintext
usage: generator.py evtx [-h] --scenario SCENARIO [--config_file CONFIG_FILE] [--input_dir INPUT_DIRECTORY] [--output_dir OUTPUT_DIRECTORY]

options:
  -h, --help            show this help message and exit
  --scenario SCENARIO, -s SCENARIO
                        Name for the tests to use for the generated tests.
  --config_file CONFIG_FILE, -c CONFIG_FILE
                        Path to the configuration INI file.
  --input_dir INPUT_DIRECTORY, -i INPUT_DIRECTORY
                        Directory where input files are located.
  --output_dir OUTPUT_DIRECTORY, -o OUTPUT_DIRECTORY
                        Directory where the Python test files will be saved.
```

## Note

The `oscap.ini` file has a weird test case. The intention may have been to test failure, I am not sure. You need to fix that manually before running the converter.

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
