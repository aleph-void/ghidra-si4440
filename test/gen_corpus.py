#!/usr/bin/env python3
"""gen_corpus.py <out.bin> [random-count] [seed]: 8-byte slots (3 content bytes + zero padding, so a sequential reference disassembler resynchronises).
Exhaustive part: every opcode x every second byte x 5 third-byte values (the third byte matters only for 3-byte
opcodes; 0x00, 0x5a, 0x80, 0xff cover the sign/zero cases of relative offsets and immediates, 0x81 is the SP address as the
destination of MOV direct,direct).
Random part: uniformly random 8-byte slots (3 content bytes + zero padding, so a sequential reference disassembler resynchronises)."""
import random
import sys
out = open(sys.argv[1], 'wb')
nrand = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
random.seed(int(sys.argv[3]) if len(sys.argv) > 3 else 7)
n = 0
for op in range(256):
    for b1 in range(256):
        for b2 in (0x00, 0x5a, 0x80, 0x81, 0xff):
            out.write(bytes([op, b1, b2, 0, 0, 0, 0, 0]))
            n += 1
for _ in range(nrand):
    out.write(bytes(random.getrandbits(8) for _ in range(3)) + bytes(5))
    n += 1
print(n, 'slots')
