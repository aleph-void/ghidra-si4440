#!/usr/bin/env python3
"""r2import_test.py <image.bin> <r2-script> <workdir>: run ghidra/r2import.py under PyGhidra (headless) on a raw image with the Si4440
language and print what it reports.  Needs PyGhidra (pip install pyghidra; GHIDRA_INSTALL_DIR set)."""
import os
import sys

import pyghidra

image, r2, work = sys.argv[1:4]
script = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'r2import.py')
os.makedirs(work, exist_ok=True)
pyghidra.run_script(image, script, project_location=work, project_name='r2t', script_args=[r2], analyze=False,
                    lang='8051:BE:24:si4440')
