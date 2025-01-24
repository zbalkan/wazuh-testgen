# wazuh-converter

A tool to convert Wazuh rule tests written as INI files to Python's `unittest` tests. It is designed to accompany `wazuh-devenv` project.

## Rationale

Wazuh uses an INI based rule testing solution. In order to get more flexibility, I used Python `unittest` package-based tests with `wazuh-devenv` project. This is a glue solution to convert INI files to Python unit test cases.

## Usage

Convert INI files to Python unittest tests. Parameters are below.

```plain
python3 src/wazuh-converter.py [args]
    --input_directory: Directory where INI files are located.
    --output_directory: Directory where the Python test files will be saved."
    --config_file: Path to the configuration INI file. (default='config.ini')
```

## Note

The `oscap.ini` file has a broken test case. Fix that manually before running the converter. This may be the case that it should fail.

The original case is below:

```ini
[OpenSCAP rule notapplicable]

oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", ...
```

Add `log 1 pass =` before the log:

```ini
[OpenSCAP rule notapplicable]

log 1 pass = oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", ...
```
