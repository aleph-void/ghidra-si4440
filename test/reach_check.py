#!/usr/bin/env python3
"""reach_check.py <reach.txt> [sleigh-source-dir]: every constructor of the compiled language must be reached.
reach.txt: merged Reach.java output ("S file:line" seen, "T file:line table" all constructors)."""
import re
import sys
seen, total = set(), {}
for l in open(sys.argv[1]):
    p = l.split()
    if p[0] == 'S':
        seen.add(p[1])
    elif p[0] == 'T':
        total[p[1]] = p[2]
missing = sorted(set(total) - seen)
print(f'   constructors reached {len(set(total) & seen)}/{len(total)}')
src = {}
for m in missing[:40]:
    f, n = m.rsplit(':', 1)
    line = ''
    try:
        line = open((sys.argv[2] if len(sys.argv) > 2 else '.') + '/' + f).read().split('\n')[int(n) - 1].strip()[:110]
    except OSError:
        pass
    print('   not reached:', m, total[m], line)
sys.exit(1 if missing else 0)
