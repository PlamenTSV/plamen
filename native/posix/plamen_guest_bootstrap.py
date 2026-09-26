#!/usr/bin/python3 -I
"""Enter the frozen Plamen driver from the fixed read-only guest mount."""

import runpy
import sys


sys.dont_write_bytecode = True
sys.path.insert(0, "/opt/plamen/scripts")
runpy.run_path("/opt/plamen/scripts/plamen_driver.py", run_name="__main__")
