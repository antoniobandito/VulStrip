#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

python -m pytest tests/test_nikto_parser.py tests/test_nmap_parser.py tests/test_subfinder_parser.py tests/test_parsers.py -v