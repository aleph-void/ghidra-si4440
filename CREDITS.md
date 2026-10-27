# Credits and provenance: Si4440 module

## Upstream

| | |
|---|---|
| Source | https://github.com/astuder/Inside-EZRadioPRO (`ghidra/8051`), HEAD `e9b9f6c4403aa43965b99080b8798cf6c16e437b` ("Si4440 die also found in EZR32HG220", 2026-04-13) |
| Ghidra-Rare fork | branch `ghidra-rare` of the aleph-void fork; the history below the Ghidra-Rare commits is the original repository's |
| License | MIT, Copyright (c) 2017 Adrian Studer (`LICENSE` in this directory is a copy of the repository's license) |
| Original authors | from `git log` of the original history (204 commits): Adrian Studer (GitHub @astuder; committed as "Adrian Studer" and "Adrian", the same address). The Si4440 variant (`ghidra/8051`) was written in January 2021 and last changed in February 2023 ("add volatile for BIT address space") |
| Based on | Ghidra's own 8051 module: `8051_main.sinc` is a copy of Ghidra's `Ghidra/Processors/8051/data/languages/8051_main.sinc` of the 10.x/9.2 era (NSA, Apache-2.0, copy of the license text in `LICENSE-Ghidra-Apache-2.0`) with the `SI4440` conditionals added by the upstream author; `si4440.slaspec`, `.pspec`, `.cspec` follow Ghidra's 8051 files. Hardware facts (memory map, interrupt vector names, XPAGE, one memory-mapped register bank) are the upstream author's reverse-engineering results (`docs/`, `radare2/`, `talks/`) |

## Other implementations

`gh search repos "ghidra si4440"`, `"EZRadioPRO sleigh"` and `"si4440 8051 disassembler"` returned nothing. No code was borrowed from elsewhere.
The upstream repository contains no files by Silicon Labs: `git ls-files` lists the author's documentation (`docs/`, `radare2/`,
`talks/` slides and PDFs, die photographs `img/` by the author and by Travis Goodspeed, credited in the README) and Python tools;
the README states that firmware images and documents generated from SiLabs binaries are not included.

## Ghidra-Rare changes

1. Packaged as an extension: `ghidra/8051` is the module directory (`data/languages/`, `Module.manifest`, `extension.properties`,
   `build.gradle`); `si4440.ldefs` replaces the upstream `8051.ldefs`, which replaced Ghidra's own file and repeated its 8051,
   80251, 80390 and mx51 languages (language id `8051:BE:24:si4440` unchanged).
2. R0-R7 are INTMEM 0-7 (varnodes of INTMEM): direct addresses 0-7 (also the second operand of `MOV direct,direct`), `@R0`/`@R1`,
   `PUSH`/`POP` and the register operands alias each other, as on the chip.
3. `NOP` has an empty body instead of a pcode op (the emulator could not run it).
4. PSW flags: ADD/ADDC/SUBB set CY, AC and OV (ADDC and SUBB include the carry in); the arithmetic and logic instructions no longer
   write PSW bits 5 and 1 (the user flags, called N and Z upstream); `MUL`, `DIV` flags; `DA A` in p-code instead of a pcodeop.
5. All bit instructions work on the containing byte (BIT_OPS SHIFTS) so that bits of internal RAM and of ACC, B, PSW are the bits
   of the bytes the other instructions use; direct address 0x81 is the SP register (`MOV SP,#n` worked on an unrelated SFR byte);
   PSW's parity bit is refreshed from ACC whenever PSW is read.
6. `MOVX @Ri`: the page is the context register `xpage` (default 0x50 in the pspec).
7. `ghidra/r2import.py`: first script argument as the r2 file, explicit `import ghidra` (PyGhidra).
8. README updates (`README.md`, `ghidra/README.md`).
9. The TODO comments inherited from Ghidra's `8051_main.sinc` are resolved or annotated (comments only).
10. Added: `CREDITS.md`, `GHIDRA-RARE.md`, `LICENSE-Ghidra-Apache-2.0`, `test/`.

## Sources and reference tools

Used as black boxes, facts or test inputs; nothing copied into the module:

- MAME's `unidasm -arch i8051` (GPL-2.0+; run as a black box, its source was not read): decode reference.
- SDCC 4.5.0 (GPL-2.0, library exception): `sdas8051` (assembler used to re-assemble the module's disassembly), `ucsim_51` (uCsim
  0.8.15, 8051 simulator, run as a black box: random single-instruction state tests; source not read) and the compiler and library
  sources used to build real test programs. Fetched from the Ubuntu packages by pinned URL and SHA-256 by `test/real-binaries.sh`.
- kokke/tiny-AES-c (Unlicense) and B-Con/crypto-algorithms SHA-256 (public domain), pinned commits, never committed.
- `test/real/demo.c` was written for this test suite (public domain).
- The MCS-51 instruction set as commonly documented (Intel MCS-51 manual operation descriptions) for the hand-computed cases; no
  manual was available offline here, the expectations were worked out by hand from the instruction semantics.
