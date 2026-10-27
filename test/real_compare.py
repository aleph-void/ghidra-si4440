#!/usr/bin/env python3
"""real_compare.py <ghidra-listing.txt> <image.bin> <rst-file>... [--base 0x8000]

ghidra-listing.txt: RealCheck.java output, "<hex address> <length> <text>" per disassembled instruction.
The rst files are SDCC's linked assembler listings: the instruction lines (the ones with a cycle count) are the ground truth
for where instructions start and how long they are.  Checks:
  1. every instruction start in the listings is disassembled by Ghidra with the same length  (missing / length differs)
  2. Ghidra disassembles nothing inside the code area that is not an instruction start of the listings  (extra)
  3. the text of every common instruction against MAME's unidasm (-arch i8051, linear sweep from the first instruction;
     compared only where unidasm is in step) with compare.py's canonical form.
Exit status 1 on any missing, length difference or text difference.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare  # noqa: E402


def main():
    args = [a for a in sys.argv[1:]]
    base = 0x8000
    if '--base' in args:
        k = args.index('--base')
        base = int(args[k + 1], 16)
        del args[k:k + 2]
    lst, img, rsts = args[0], args[1], args[2:]
    truth = {}
    mnem = {}
    dead = set()      # instructions no flow reaches: after RET/RETI/LJMP/SJMP/AJMP with no label in between
    for r in rsts:
        prev, label = None, False
        for l in open(r, errors='replace'):
            if re.match(r'\s+[0-9A-F]{6}\s+\d+ [A-Za-z_][\w$]*::?\s*$', l) or re.match(r'\s+[0-9A-F]{6}\s+\d+ \d+\$:', l):
                label = True
                continue
            m = re.match(r'\s*([0-9A-F]{6})((?: [0-9A-F]{2})+)\s+\[\d+\]\s*\d+\s+\t(\S+)', l)
            if m:
                a = int(m.group(1), 16)
                truth[a] = len(m.group(2).split())
                mnem[a] = m.group(3)
                if prev in ('ret', 'reti', 'ljmp', 'sjmp', 'ajmp') and not label:
                    dead.add(a)
                prev, label = m.group(3), False
            elif re.match(r'\s+[0-9A-F]{6}\s', l) and '.ds' in l:
                label = True          # reserved space (e.g. between interrupt vectors): what follows is placed, not fallen into
    gh = {}
    for l in open(lst):
        a, n, t = l.rstrip('\n').split(' ', 2)
        gh[int(a, 16)] = (int(n), t)
    lo, hi = min(truth), max(truth) + 3
    missing_all = [a for a in truth if a not in gh]
    # never executed, not reachable by flow: the NOPs of SDCC's atomic helpers (rollback markers) and instructions placed
    # after an unconditional jump or return without a label (a second RET emitted by the compiler)
    nops = [a for a in missing_all if mnem[a] == 'nop' or a in dead]
    missing = [a for a in missing_all if not (mnem[a] == 'nop' or a in dead)]
    lendiff = [a for a in truth if a in gh and gh[a][0] != truth[a]]
    extra = [a for a in gh if lo <= a <= hi and a not in truth]
    # unidasm over the code area
    data = open(img, 'rb').read()[lo:hi]
    tmp = os.path.join(os.environ.get('TMPDIR', '/tmp'), 'rc_%d.bin' % os.getpid())
    open(tmp, 'wb').write(data)
    out = subprocess.run(['unidasm', tmp, '-arch', 'i8051', '-basepc', '0x%x' % lo], capture_output=True, text=True).stdout
    os.unlink(tmp)
    ref = {}
    for l in out.splitlines():
        m = re.match(r'([0-9a-fA-F]+): ((?:[0-9a-fA-F]{2} ?)+)\s+(.*)$', l)
        if m:
            bs = m.group(2).split()
            ref[int(m.group(1), 16)] = (len(bs), m.group(3))
    compare.learn_names()
    agree = diff = skipped = 0
    ex = []
    for a in sorted(truth):
        if a not in gh:
            continue
        if a not in ref or ref[a][0] != gh[a][0]:
            skipped += 1
            continue
        g, r = compare.canon(gh[a][1], a), compare.canon(ref[a][1], a, True)
        if g == r:
            agree += 1
        else:
            diff += 1
            if len(ex) < 8:
                ex.append('%04x: module %s   unidasm %s' % (a, gh[a][1], ref[a][1]))
    print(f'   listing instructions {len(truth)}: missing in Ghidra {len(missing)} (+{len(nops)} unreachable: NOP padding of the SDCC atomic helpers, code after an unconditional jump or return), length differs {len(lendiff)}; '
          f'Ghidra instructions in the code area that are not listing instructions {len(extra)}')
    print(f'   text against unidasm: {agree} agree, {diff} differ, {skipped} not compared (unidasm out of step)')
    for e in ex:
        print('      ', e)
    for a in missing[:5]:
        print('       missing: %04x' % a)
    for a in extra[:5]:
        print('       extra: %04x %s' % (a, gh[a][1]))
    sys.exit(1 if missing or lendiff or diff else 0)


if __name__ == '__main__':
    main()
