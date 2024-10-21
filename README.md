# wazuh-converter

A tool to convert Wazuh rule tests written as INI files to Python's `unittest` tests. It is designed to accompany `wazuh-devenv` project.

## Rationale

Wazuh sues an INI based rule testing solution. In order to get more flexibility, I used Python `unittest` package-based tests. This is a glue solution to convert INI files to Python unit test cases I used with `wazuh-devenv` project.

## Usage

Convert INI files to Python unittest tests. Parameters are below.

```plain
    --input_directory: Directory where INI files are located.
    --output_directory: Directory where the Python test files will be saved."
    --config_file: Path to the configuration INI file. (default='config.ini')
```
