#!/usr/bin/env python3
"""Random single-instruction state tests: SDCC's uCsim 8051 simulator (a black box) against the module's p-code.

  sem_gen.py <ghidra.txt> <out-dir> [tests-per-opcode] [seed]      -> out-dir/tests.txt (SemCheck.java input)

For every opcode (A5 is reserved) tests-per-opcode instructions are built with random operands (operand roles per opcode
come from the 8051 manual's encoding tables; the lengths are checked against the module's decode); direct and bit
operands are drawn from internal RAM, R0-R7 and the CPU-state SFRs (SP, DPL, DPH, PSW, ACC, B) because other SFRs are
peripherals.  uCsim (type C52) runs one step from a random state (A, B, PSW with register bank 0, SP, DPTR, 256 bytes of
internal RAM, random memory behind DPTR, @R0/@R1 MOVX space at 0x5000 = P2 0x50, MOVC windows) and its final state is the
expectation for one emulator step of the module's p-code.  Tests that would leave register bank 0 (PSW RS0/RS1 written) are
dropped: the variant models only the memory-mapped bank 0.  PSW bit 0 (parity) is compared on reads only: the module
refreshes it when PSW is read, uCsim keeps it live.
"""
import os
import random
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

UCSIM = os.environ.get('UCSIM_51') or os.path.expanduser('~/.cache/ghidra-rare-scratch/tools/sdcc-root/usr/bin/ucsim_51')
CODE = 0x2000
WINS = [(0x0000, 0x1200), (0x5000, 0x5100)]       # compared (and identical code/xram) windows
SPECIAL = [0x81, 0x82, 0x83, 0xd0, 0xe0, 0xf0]


def layout(op):
    """operand roles after the opcode byte: d direct, b bit, r rel8, i imm8, w imm16, a address low byte (AJMP/ACALL), L addr16"""
    lo, hi = op & 15, op >> 4
    if lo == 1:
        return 'a'
    if op in (0x02, 0x12):
        return 'L'
    if op == 0x90:
        return 'w'
    if op in (0x10, 0x20, 0x30):
        return 'br'
    if op in (0x40, 0x50, 0x60, 0x70, 0x80) or (lo >= 8 and hi == 0xd):
        return 'r'
    if op in (0x42, 0x52, 0x62, 0xc0, 0xd0, 0x05, 0x15, 0xe5, 0xf5, 0xc5) or (lo == 5 and hi in (2, 3, 4, 5, 6, 9)):
        return 'd'
    if op in (0x43, 0x53, 0x63):
        return 'di'
    if op == 0x75:
        return 'di'
    if op == 0x85:
        return 'dd'
    if op in (0x72, 0x82, 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xa0, 0xb0):
        return 'b'
    if op == 0xb5 or op == 0xd5:
        return 'dr'
    if lo == 4 and hi in (2, 3, 4, 5, 6, 7, 9):
        return 'i'
    if op == 0xb4 or (hi == 0xb and lo >= 6):
        return 'ir'
    if hi == 7 and lo >= 6:
        return 'i'
    if (hi == 8 or hi == 0xa) and lo >= 6:
        return 'd'
    return ''


def draw(role, rnd, op):
    if role == 'd':
        c = rnd.random()
        if c < 0.55:
            return rnd.randrange(0x08, 0x80)
        if c < 0.75:
            return rnd.randrange(0, 8)
        # PUSH SP and POP SP are left to the documentation: the instruction manual's operation text (increment SP / store, or
        # load / decrement SP) fixes an order that uCsim does not follow when the operand is SP itself (uCsim pushes the old
        # SP and ends POP SP with the popped value); real silicon is not known here, nobody writes this
        return rnd.choice([x for x in SPECIAL if not (op in (0xc0, 0xd0) and x == 0x81)])
    if role == 'b':
        c = rnd.random()
        if c < 0.6:
            return rnd.randrange(0, 0x80)
        return rnd.choice([0xe0, 0xf0, 0xd0]) + rnd.randrange(8)
    if role == 'r':
        return rnd.randrange(-30, 31) & 255
    return rnd.randrange(256)


def build(op, rnd):
    code = [op]
    for role in layout(op):
        if role == 'a':
            code.append(rnd.randrange(256))
        elif role == 'L':
            v = rnd.randrange(0x2000, 0x3000)
            code += [v >> 8, v & 255]
        elif role == 'w':
            code += [rnd.randrange(0x1000) >> 8, rnd.randrange(256)]
        else:
            code.append(draw(role, rnd, op))
    return bytes(code)


def run_ucsim(t, tmp, tag):
    ih = []
    code = t['code']
    b = bytes([len(code), CODE >> 8, CODE & 255, 0]) + code
    ih.append(':' + (b + bytes([(-sum(b)) & 255])).hex().upper())
    ih.append(':00000001FF')
    hx = os.path.join(tmp, tag + '.hex')
    open(hx, 'w').write('\n'.join(ih) + '\n')

    def setmem(sp, addr, data):
        out = []
        for i in range(0, len(data), 64):
            out.append('set memory %s 0x%x %s' % (sp, addr + i, ' '.join('%d' % x for x in data[i:i + 64])))
        return out
    cmds = []
    cmds += setmem('iram', 0, t['iram'])
    for (lo, hi) in WINS:
        cmds += setmem('xram', lo, t['win'][lo])
        cmds += setmem('rom', lo, t['win'][lo])
    cmds += setmem('rom', CODE + len(code), t['win2'][len(code):])
    cmds += setmem('rom', CODE, code)
    cmds += ['set memory sfr 0xa0 0x50', 'set memory sfr 0x81 %d' % t['SP'], 'set memory sfr 0x82 %d' % (t['DPTR'] & 255),
             'set memory sfr 0x83 %d' % (t['DPTR'] >> 8), 'set memory sfr 0xe0 %d' % t['A'], 'set memory sfr 0xf0 %d' % t['B'],
             'set memory sfr 0xd0 %d' % t['PSW'], 'pc 0x%x' % CODE, 'step', 'info registers', 'dump iram 0 255']
    for (lo, hi) in WINS:
        cmds.append('dump xram 0x%x 0x%x' % (lo, hi - 1))
    cmds.append('quit')
    try:
        r = subprocess.run([UCSIM, '-t', 'C52', '-c', '-', hx], input='\n'.join(cmds) + '\n', capture_output=True, text=True,
                           errors='replace', timeout=60)
    except subprocess.TimeoutExpired:
        return None
    out = r.stdout
    k = out.find('Stop at')
    if k < 0:
        return None
    out = out[k:]
    m = re.search(r'Stop at 0x([0-9a-f]+)', out)
    acc = re.search(r'ACC= 0x([0-9a-f]{2})', out)
    bb = re.search(r' B= 0x([0-9a-f]{2})', out)
    psw = re.search(r'PSW= 0x([0-9a-f]{2})', out)
    sp = re.search(r'SP 0x([0-9a-f]{2})', out)
    dptr = re.search(r'DPTR= 0x([0-9a-f]{4})', out)
    if not (m and acc and bb and psw and sp and dptr):
        return None
    # dumps: lines "0xADDR   hh hh hh ..." after the register block; separate the iram dump from the xram dumps by address order
    lines = [(int(a, 16), bytes.fromhex(h.replace(' ', ''))) for a, h in
             re.findall(r'^0x([0-9a-f]+)\s+((?:[0-9a-f]{2} ){8})', out[out.find('dump iram') if 'dump iram' in out else 0:], re.M)]
    # the first lines (up to the xram dump) are iram
    seq = [(a, d) for a, d in lines]
    # split: iram = first 32 lines (256 bytes, address 0x00-0xf8); the rest are the xram windows
    iram = bytearray(256)
    for a, d in seq[:32]:
        iram[a:a + 8] = d
    win = {}
    rest = seq[32:]
    for (lo, hi) in WINS:
        buf = bytearray(hi - lo)
        for a, d in rest:
            if lo <= a < hi:
                buf[a - lo:a - lo + 8] = d
        win[lo] = bytes(buf)
    if len(rest) < sum((hi - lo) // 8 for lo, hi in WINS):
        return None
    return dict(PC=int(m.group(1), 16), A=int(acc.group(1), 16), B=int(bb.group(1), 16), PSW=int(psw.group(1), 16),
                SP=int(sp.group(1), 16), DPTR=int(dptr.group(1), 16), iram=bytes(iram), win=win)


def parity(x):
    return bin(x).count('1') & 1


def main():
    gh, outdir = sys.argv[1:3]
    per = int(sys.argv[3]) if len(sys.argv) > 3 else 40
    rnd = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
    os.makedirs(outdir, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix='sem.', dir=os.environ.get('TMPDIR', '/tmp'))
    # check the operand layout table against the module's decoder (the exhaustive part of the corpus: 256 x 256 x 5 slots)
    lens = {}
    for k, l in enumerate(open(gh)):
        if k >= 256 * 256 * 5:
            break
        lens.setdefault(k // 1280, set()).add(int(l.split(' ', 2)[1]))
    for op in range(256):
        if op == 0xa5:
            continue
        want = 1 + sum({'a': 1, 'L': 2, 'w': 2}.get(c, 1) for c in layout(op))
        assert lens[op] == {want}, (hex(op), lens[op], want)
    tests = []
    for op in range(256):
        if op == 0xa5:
            continue
        for _ in range(per):
            c = build(op, rnd)
            win = {lo: bytes(rnd.randrange(256) for _ in range(hi - lo)) for lo, hi in WINS}
            w2 = bytes(rnd.randrange(256) for _ in range(0x200))
            A = rnd.randrange(256)
            psw = (rnd.randrange(256) & 0xe7 & ~1) | parity(A)
            # R0/R1 pointer cases: sometimes keep them below 0x80, sometimes anything
            iram = bytearray(rnd.randrange(256) for _ in range(256))
            sp = rnd.randrange(0x10, 0xf0)
            dptr = rnd.randrange(0, 0x1000)
            tests.append(dict(code=c, win=win, win2=w2, A=A, B=rnd.randrange(256), PSW=psw, SP=sp, DPTR=dptr, iram=bytes(iram)))

    def one(k):
        return run_ucsim(tests[k], tmp, 't%d' % k)
    with ThreadPoolExecutor(int(os.environ.get('JOBS', '8'))) as ex:
        results = list(ex.map(one, range(len(tests))))
    n = skipped = 0
    with open(os.path.join(outdir, 'tests.txt'), 'w') as f:
        for k, (t, r) in enumerate(zip(tests, results)):
            if r is None:
                skipped += 1
                continue
            if r['PSW'] & 0x18:             # left register bank 0: the variant models bank 0 only
                skipped += 1
                continue
            code = t['code']
            init = [f"ACC={t['A']:x}", f"B={t['B']:x}", f"PSW={t['PSW']:x}", f"SP={t['SP']:x}", f"DPTR={t['DPTR']:x}",
                    f"INTMEM#256:0={t['iram'].hex()}"]
            for lo, hi in WINS:
                init.append(f"RAM#{hi - lo}:{lo:x}={t['win'][lo].hex()}")
            init.append(f"RAM#{len(t['win2'])}:{CODE:x}={t['win2'].hex()}")
            init.append(f"RAM#{len(code)}:{CODE:x}={code.hex()}")
            exp = [f"ACC={r['A']:x}", f"B={r['B']:x}", f"PSW&fe={r['PSW']:x}", f"SP={r['SP']:x}", f"DPTR={r['DPTR']:x}",
                   f"PC={r['PC']:x}", f"INTMEM#256:0={r['iram'].hex()}"]
            for lo, hi in WINS:
                exp.append(f"RAM#{hi - lo}:{lo:x}={r['win'][lo].hex()}")
            f.write(f"{code.hex()}#{k} {','.join(init)} {','.join(exp)}\n")
            n += 1
    print(len(tests), 'cases;', n, 'tests written,', skipped, 'dropped (simulator failure or left register bank 0)')


if __name__ == '__main__':
    main()
