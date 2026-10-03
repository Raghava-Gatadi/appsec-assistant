#!/usr/bin/env python3
"""No-install entry point: python3 scan.py /path/to/source -o report.html"""
import sys

if sys.version_info < (3, 11):
    raise SystemExit("AppSec Assistant requires Python 3.11 or newer.")

from appsec_assistant.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
