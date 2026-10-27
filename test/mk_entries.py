#!/usr/bin/env python3
"""mk_entries.py <linker.map> <out.txt> <rst-file>...: entry points for RealCheck.java.
The reset vector (8000), every code-area global of the linker map and every C function label ('_name:') or exported routine ('name::') of
SDCC's linked listings that starts an instruction, and the slots of SDCC's interrupt vector table (data tables in the code area are skipped): the functions that nothing calls (library helpers, static
functions reached through a function-pointer table) cannot be found by flow analysis, a symbol table would name them."""
import re
import sys
instr = set()
labels = {}
for r in sys.argv[3:]:
    lines = open(r, errors='replace').read().split('\n')
    invect = False
    for i, l in enumerate(lines):
        m = re.match(r'\s+([0-9A-F]{6})((?: [0-9A-F]{2})+)\s+(\[\d+\])', l)
        if m:
            instr.add(int(m.group(1), 16))
            if invect:            # SDCC's interrupt vector table at the start of the code: each slot is entered by an interrupt
                labels.setdefault(int(m.group(1), 16), 'vector_%s' % m.group(1)[2:])
        if re.match(r'\s+[0-9A-F]{6}\s+\d+ ', l) and l.rstrip().endswith(':'):
            invect = l.rstrip().endswith('__interrupt_vect:')
        # C functions (static ones too) are '_name:', exported assembler routines 'name::'; plain 'name:' labels of the
        # assembler sources are branch targets inside a routine, not functions
        m = re.match(r'\s+([0-9A-F]{6})\s+\d+ ([A-Za-z_]\w*)(::?)\s*$', l)
        if m and (m.group(3) == '::' or m.group(2).startswith('_')):
            labels.setdefault(int(m.group(1), 16), m.group(2).lstrip('_'))
ent = {0x8000: 'reset'}
for l in open(sys.argv[1]):
    m = re.match(r'C:\s+0000([0-9A-F]{4})\s+(\S+)\s', l)
    if m and not m.group(2).startswith(('s_', 'l_')):
        labels.setdefault(int(m.group(1), 16), m.group(2).lstrip('_'))
for a, n in labels.items():
    if a >= 0x8000 and a in instr:
        ent.setdefault(a, n)
open(sys.argv[2], 'w').write('\n'.join(f'{n} {a:x}' for a, n in sorted(ent.items())) + '\n')
