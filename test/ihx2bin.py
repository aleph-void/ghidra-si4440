#!/usr/bin/env python3
"""ihx2bin.py <in.ihx> <out.bin>: Intel hex -> flat 64 KB image (code and external data share one 16-bit space)."""
import sys
img = bytearray(65536)
lo, hi = 0xffff, 0
for l in open(sys.argv[1]):
    l = l.strip()
    if not l.startswith(':'):
        continue
    n, a, t = int(l[1:3], 16), int(l[3:7], 16), int(l[7:9], 16)
    if t == 0:
        img[a:a + n] = bytes.fromhex(l[9:9 + 2 * n])
        lo, hi = min(lo, a), max(hi, a + n)
# The part's reset and interrupt vectors live at 0x0000-0x0052 (RAM); an image that only holds the boot ROM code at 0x8000 leaves them
# empty: reset jumps to the ROM entry, every other vector is a RETI, so that no zero fill is analysed as vector code.
if lo >= 0x8000:
    img[0:3] = bytes([0x02, lo >> 8, lo & 255])
    for a in range(3, 0x53):
        img[a] = 0x32 if a % 4 == 3 else 0x00
open(sys.argv[2], 'wb').write(img)
print('0x%04x-0x%04x' % (lo, hi))
