#!/usr/bin/env python3
"""emu_tests.py <workdir>: write emu.bin (64 KB image holding every case's code) and tests.txt for EmuCheck.java.

Cases come from emu_cases.py.  Automatic start addresses: 0x8000 + n * 0x40; cases that need a fixed address give it.
"{S+n}" in an init / expect item is replaced by start + n (hex)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import emu_cases  # noqa: E402


def main():
    work = sys.argv[1]
    os.makedirs(work, exist_ok=True)
    img = bytearray(65536)
    lines = []
    for n, case in enumerate(emu_cases.CASES):
        name, code, init, expect = case[:4]
        start = case[4] if len(case) > 4 and case[4] is not None else 0x8000 + n * 0x40
        code = bytes.fromhex(code)
        stop = (start + (case[5] if len(case) > 5 and case[5] is not None else len(code))) & 0xffff
        img[start:start + len(code)] = code

        def sub(t):
            return re.sub(r'\{S([+-]\d+)?\}', lambda m: '%x' % (start + int(m.group(1) or 0)), t)
        lines.append(f'{name} {start:x} {stop:x} {sub(init) or "-"} {sub(expect) or "-"}')
    open(os.path.join(work, 'emu.bin'), 'wb').write(img)
    open(os.path.join(work, 'tests.txt'), 'w').write('\n'.join(lines) + '\n')
    print(len(emu_cases.CASES), 'cases')


if __name__ == '__main__':
    main()
