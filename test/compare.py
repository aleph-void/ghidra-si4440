#!/usr/bin/env python3
"""compare.py <ghidra.txt> <reference.txt> [--show N] [--corpus all.bin]

ghidra.txt: DumpSlots output ("<slot> <length> <text>").
reference.txt: MAME `unidasm -arch i8051` output over the same 8-byte-slot corpus (lines "ADDR: bb bb  text"; only the
lines at slot starts are used).
Both texts are reduced to one canonical form: lower case, numbers as integers, branch targets masked to 16 bits, SFR
names replaced by their addresses, rbXrY by the direct address (bank 0 shown as r0-r7 by both tools), bit operands as
bit-address numbers.  Classes: agree, both invalid, length differs, text differs, one-sided decodes.
Exit status 1 when a class that is not in EXPLAINED is non-empty.
"""
import re
import sys
from collections import Counter, defaultdict

SFR0 = {'p0': 0x80, 'sp': 0x81, 'dpl': 0x82, 'dph': 0x83, 'pcon': 0x87, 'tcon': 0x88, 'tmod': 0x89, 'tl0': 0x8a,
       'tl1': 0x8b, 'th0': 0x8c, 'th1': 0x8d, 'p1': 0x90, 'scon': 0x98, 'sbuf': 0x99, 'p2': 0xa0, 'ie': 0xa8,
       'p3': 0xb0, 'ip': 0xb8, 'psw': 0xd0, 'acc': 0xe0, 'b': 0xf0}


SFR = {}
BITNAME = {}


def learn_names():
    """SFR and bit names of the reference, learned from its own output for PUSH direct (c0 xx) and CLR bit (c2 xx)."""
    import os
    import subprocess
    import tempfile
    blob = b''.join(bytes([op, b, 0, 0, 0, 0, 0, 0]) for op in (0xc0, 0xc2) for b in range(256))
    d = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
    p = os.path.join(d, 'n.bin')
    open(p, 'wb').write(blob)
    out = subprocess.run(['unidasm', p, '-arch', 'i8051'], capture_output=True, text=True).stdout
    os.unlink(p)
    os.rmdir(d)
    for l in out.splitlines():
        m = re.match(r'([0-9a-fA-F]+): ((?:[0-9a-fA-F]{2} ?)+)\s+(.*)$', l)
        if m and int(m.group(1), 16) % 8 == 0:
            bs, op = m.group(2).split(), m.group(3).split()
            if len(op) > 1 and len(bs) == 2 and not op[1].startswith(('$', 'rb')):
                if bs[0] == 'c0':
                    SFR[op[1]] = int(bs[1], 16)
                elif bs[0] == 'c2':
                    BITNAME[op[1]] = int(bs[1], 16)


def num(s):
    s = s.strip()
    if s.startswith('$'):
        return int(s[1:], 16)
    if s.startswith('0x'):
        return int(s, 16)
    return int(s)


def bit(byte, n):
    return (byte - 0x20) * 8 + n if byte < 0x80 else byte + n


def canon_op(o, mn, slot, ref=False):
    o = o.strip().lower()
    if ref and o == 'cy':      # the reference names bit D7 'cy' and the carry operand 'c'
        return 'bit%d' % BITNAME['cy']
    if o.startswith('#'):
        return '#%d' % num(o[1:])
    if o.startswith('/'):
        return '/' + canon_op(o[1:], mn, slot, ref)
    if o in ('a', 'c', 'cy', 'ab', 'dptr', '@a+dptr', '@a+pc', '@dptr', '@r0', '@r1') or re.fullmatch(r'r[0-7]', o):
        return 'c' if o == 'cy' else o
    m = re.fullmatch(r'rb([0-3])r([0-7])', o)
    if m:
        return 'r%s' % m.group(2) if m.group(1) == '0' else str(8 * int(m.group(1)) + int(m.group(2)))
    if o in BITNAME:
        return 'bit%d' % BITNAME[o]
    m = re.fullmatch(r'([a-z0-9$]+)\.([0-7])', o)
    if m:
        b = m.group(1)
        return 'bit%d' % bit(SFR[b] if b in SFR else num(b if b.startswith('$') else '0x' + b), int(m.group(2)))
    if o in SFR:
        return 'a' if o == 'acc' else str(SFR[o])
    return str(num(o) & 0xffff) if o[0] in '$0' and (mn.startswith(('a', 'l', 's', 'j', 'd', 'c')) and slot is not None) else str(num(o))


BITOPS = ('jbc', 'jb', 'jnb', 'setb', 'clr', 'cpl', 'mov', 'orl', 'anl')


def canon(t, slot=None, ref=False):
    t = t.strip().lower()
    if t in ('bad', 'ill/rsv') or t.startswith('ill'):
        return None
    m = re.match(r'(\S+)\s*(.*)$', t)
    mn, rest = m.group(1), m.group(2)
    ops = [x for x in rest.split(',') if x] if rest else []
    out = []
    for k, o in enumerate(ops):
        o = o.strip()
        # a bare number in a bit-operand position is a bit address
        if re.fullmatch(r'(0x[0-9a-f]+|/0x[0-9a-f]+)', o) and mn in BITOPS:
            neg = o.startswith('/')
            v = num(o[1:] if neg else o)
            isbit = (mn in ('jbc', 'jb', 'jnb', 'setb', 'clr', 'cpl') and k == 0) or \
                    (mn in ('orl', 'anl', 'mov') and ((k == 1 and ops[0].strip() in ('c', 'cy')) or (k == 0 and len(ops) == 2 and ops[1].strip() in ('c', 'cy'))))
            if isbit:
                out.append('/bit%d' % v if neg else 'bit%d' % v)
                continue
        out.append(canon_op(o, mn, slot, ref))
    return mn + ' ' + ','.join(out)


def main():
    learn_names()
    gh = [l.rstrip('\n').split(' ', 2) for l in open(sys.argv[1])]
    ref = {}
    for l in open(sys.argv[2]):
        m = re.match(r'([0-9a-fA-F]+): ((?:[0-9a-fA-F]{2} ?)+)\s+(.*)$', l.rstrip('\n'))
        if m is None:
            m = re.match(r'([0-9a-fA-F]+): ((?:[0-9a-fA-F]{2} ?)+)\s*$', l)
            continue
        a = int(m.group(1), 16)
        bs = m.group(2).split()
        if a % 8 == 0:
            ref[a // 8] = (len(bs), m.group(3))
            # learn the reference's SFR and bit names from its own output for PUSH direct (c0) and CLR bit (c2)
            op = m.group(3).split()
            if bs[0] == 'c0' and len(op) > 1 and not op[1].startswith('$') and not op[1].startswith('rb'):
                SFR[op[1]] = int(bs[1], 16)
            if bs[0] == 'c2' and len(op) > 1 and not op[1].startswith('$') and not re.fullmatch(r'[a-z0-9]+\.[0-7]', op[1]):
                BITNAME[op[1]] = int(bs[1], 16)
            if bs[0] == 'c2' and len(op) > 1 and re.fullmatch(r'[a-z0-9]+\.[0-7]', op[1]):
                BITNAME[op[1]] = int(bs[1], 16)
    show = int(sys.argv[sys.argv.index('--show') + 1]) if '--show' in sys.argv else 4
    corpus = open(sys.argv[sys.argv.index('--corpus') + 1], 'rb').read() if '--corpus' in sys.argv else b''
    cnt = Counter()
    ex = defaultdict(list)
    for i, gl, gt in gh:
        i = int(i)
        rl, rt = ref[i]
        g, r = canon(gt, i), canon(rt, i, True)
        bytes_ = corpus[i * 8:i * 8 + 3].hex() if corpus else ''
        if g is None and r is None:
            k = 'both invalid'
        elif g is None:
            k = 'reference decodes, module rejects'
        elif r is None:
            k = 'module decodes, reference rejects'
        elif int(gl) != rl:
            k = 'length differs'
        elif g == r:
            k = 'agree'
        else:
            k = 'text differs'
        cnt[k] += 1
        if len(ex[k]) < show and k not in ('agree', 'both invalid'):
            ex[k].append(f'{bytes_}  module: {gt}   reference: {rt}   [{g} | {r}]')
    total = sum(cnt.values())
    print(f'   {total} slots')
    for k, v in sorted(cnt.items(), key=lambda kv: -kv[1]):
        print(f'   {k:45s} {v:8d}')
        for e in ex[k]:
            print('       ' + e)
    bad = [k for k in cnt if k not in ('agree', 'both invalid') and k not in EXPLAINED]
    sys.exit(1 if bad else 0)


EXPLAINED = set()

if __name__ == '__main__':
    main()
