#!/usr/bin/env python3
"""asm_roundtrip.py <ghidra.txt> <corpus.bin> <out-ok.txt> [stride]

Re-assemble the module's disassembly with SDCC's sdas8051 (a second, independent reference) and compare the bytes with the
original ones.  Every <stride>-th slot of the corpus is checked (default: all).  AJMP / ACALL are not checked here:
sdas8051 leaves their page bits to the linker (the listing shows the unrelocated opcode).  Slots in which the module's
text uses A as a direct address (E0) are assembled with 0xE0.
Prints agree / differ / not-assembled counts; slot numbers that agree are written to <out-ok.txt>.
Environment: SDAS8051 (default: sdas8051 on PATH or the SDCC tree under ~/.cache/ghidra-rare-scratch/tools).
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

SDAS = os.environ.get('SDAS8051') or shutil.which('sdas8051') or os.path.expanduser(
    '~/.cache/ghidra-rare-scratch/tools/sdcc-root/usr/bin/sdas8051')
EQU = {'DPL': 0x82, 'DPH': 0x83, 'PSW': 0xd0, 'B': 0xf0}


def to_asm(text, addr, length, dA=0, rn=0):
    """dA: 0 as printed, 1 every A is the direct address 0xE0, 2 only the last A is, 3 only the first A is.
    rn: 0 as printed, 1 every R0-R7 is the direct address 0-7, 2 only the first is, 3 only the last is."""
    m = re.match(r'(\S+)\s*(.*)$', text)
    mn, rest = m.group(1).lower(), m.group(2)
    if mn in ('ajmp', 'acall'):
        return None
    ops = rest.split(',') if rest else []
    rpos = [k for k, o in enumerate(ops) if re.fullmatch(r'R[0-7]', o)]
    apos = [k for k, o in enumerate(ops) if o == 'A']
    out = []
    for k, o in enumerate(ops):
        if o in EQU:
            o = '0x%02x' % EQU[o]
        elif o == 'A' and (dA == 1 or (dA == 2 and k == apos[-1]) or (dA == 3 and k == apos[0])):
            o = '0xe0'
        elif o == 'CY':
            o = 'c'
        elif re.fullmatch(r'0x[0-9a-f]+', o) and (mn in ('sjmp', 'jc', 'jnc', 'jz', 'jnz', 'jb', 'jnb', 'jbc', 'cjne', 'djnz') and k == len(ops) - 1):
            o = '.%+#x' % ((((int(o, 16) - addr) + 0x8000) & 0xffff) - 0x8000)
        elif k in rpos and (rn == 1 or (rn == 2 and k == rpos[0]) or (rn == 3 and k == rpos[-1])):
            o = '0x0' + o[1]
        out.append(o.lower() if o.startswith(('@', 'R')) else o)
    return '\t' + mn + ' ' + ','.join(out)


def assemble(lines):
    d = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
    src = os.path.join(d, 'r.asm')
    with open(src, 'w') as f:
        f.write('\t.area ABS (ABS,OVR)\n')
        for tag, addr, asm in lines:
            f.write(f'\t.org 0x{addr:x}\n{asm}\n')
    subprocess.run([SDAS, '-plosgff', src], capture_output=True, cwd=d)
    res = {}
    # listing lines of assembled instructions: "<addr> <bytes>   [cycles]<line number> <tab> text" (the line number follows the
    # bracket directly once it has five digits)
    for l in open(os.path.join(d, 'r.lst'), errors='replace'):
        m = re.match(r'^\s*([0-9A-F]{6}) ((?:[0-9A-F]{2})(?: [0-9A-F]{2})*)\s+\[\d+\]\s*\d+\s+\t', l)
        if m:
            res[int(m.group(1), 16)] = bytes.fromhex(m.group(2).replace(' ', ''))
    shutil.rmtree(d)
    return res


def main():
    gh = [l.rstrip('\n').split(' ', 2) for l in open(sys.argv[1])]
    corpus = open(sys.argv[2], 'rb').read()
    stride = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    agree, differ, nasm, skipped = [], [], [], 0
    direct07 = 0
    batch = []
    ex = []
    # one assembly run per 64 KB-aligned chunk of slots so that every instruction has a unique address
    CH = 8192
    for c0 in range(0, len(gh), CH):
        todo = []
        for i, ln, t in gh[c0:c0 + CH]:
            i = int(i)
            if i % stride or ln == '0' or t == 'BAD':
                continue
            addr = (i * 8) & 0xffff
            asm = to_asm(t, addr, int(ln))
            if asm is None:
                skipped += 1
                continue
            todo.append((i, addr, asm))
        # variants of the module's text: as printed, A as the direct address 0xE0, Rn as the direct address n, both
        left = {i: (addr, None) for i, addr, _ in todo}
        for dA, rn in [(0, 0)] + [(a, r) for r in (0, 1, 2, 3) for a in (0, 1, 2, 3) if (a, r) != (0, 0)]:
            if not left:
                break
            batch = []
            for i, (addr, _) in left.items():
                a = to_asm(gh[i][2], addr, int(gh[i][1]), dA, rn)
                if a is not None:
                    batch.append((i, addr, a))
            res = assemble(batch)
            for i, addr, a in batch:
                got = res.get(addr)
                want = corpus[i * 8:i * 8 + int(gh[i][1])]
                if got == want:
                    agree.append(i)
                    direct07 += 1 if rn else 0
                    del left[i]
                elif got is not None:
                    left[i] = (addr, (got, a))
        for i, (addr, last) in left.items():
            if last is None:
                nasm.append(i)
            else:
                differ.append(i)
                if len(ex) < 12:
                    ex.append(f'{corpus[i * 8:i * 8 + int(gh[i][1])].hex()}: module {gh[i][2]} -> {last[1].strip()} -> {last[0].hex()}')
    print(f'   sdas8051 round trip: {len(agree)} identical bytes, {len(differ)} differ, {len(nasm)} not assembled, '
          f'{skipped} AJMP/ACALL not checked; {direct07} of the identical ones show a direct address 0-7 as Rn (memory mapped bank)')
    for e in ex:
        print('       ' + e)
    for i in nasm[:6]:
        print('       not assembled:', corpus[i * 8:i * 8 + 3].hex(), gh[i][2])
    open(sys.argv[3], 'w').write('\n'.join(map(str, agree)) + '\n')
    sys.exit(1 if differ or nasm else 0)


if __name__ == '__main__':
    main()
