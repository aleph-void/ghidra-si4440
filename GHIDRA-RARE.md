# Si4440 (Silicon Labs EZRadioPRO 8051 variant) in Ghidra-Rare: verification notes

Source: https://github.com/astuder/Inside-EZRadioPRO, `ghidra/8051` (MIT), see [CREDITS.md](CREDITS.md) for provenance and every change.
Language: `8051:BE:24:si4440` (upstream id unchanged; "SiLabs EZRadioPRO family", an 8051 variant with a flat 16-bit memory map).
Builds for Ghidra 12.1.3, 12.1.4 and 12.2 (`tools/build-module.sh --standard --name Si4440`).

## What the instruction set is

The EZRadioPRO (Si4440, Si4455, Si4463, Si4362, Si4467, ... and the EZR32 radio die) runs its digital part on an 8051 core. The
author's documentation (`docs/`, the r2con 2018 and Teardown 2019 talks, `radare2/`) describes only memory-model differences, and
the module implements exactly those; **the instruction set is the standard MCS-51 one (255 opcodes, `A5` reserved), no extra opcodes**.
Compared with Ghidra's stock `8051` language the variant:

- has one flat 16-bit address space (`RAM`) for code and external data (the firmware dump is a single 64 KB image: RAM at
  0x0000-0x07ff, XREG at 0x5000, a mirror of INTMEM at 0x5400, NVM at 0x5500, ROM at 0x8000-0xffff), where the stock language has
  separate `CODE` and `EXTMEM` spaces;
- reaches `MOVX @R0/@R1` at `XPAGE:Ri` with `XPAGE` = 0x50 (context register `xpage`, default 0x50);
- maps only register bank 0, R0-R7 = INTMEM 0-7 (the stock language keeps R0-R7 in the register space and never aliases them);
- has the SFR set the part implements and memory-mapped bits for A, B, IE, IP, PSW;
- has the reset vector (0x0000), the interrupt vectors 0x0003-0x0043 and the boot loader vectors (0x8000, 0x8003, 0x801f, 0x8043) as entry points,
  and volatile ranges for the register areas.

The "oracles" (MAME `unidasm`, SDCC's `sdas8051` and uCsim) know the standard 8051 only, so they verify the instruction set and the
semantics of the standard instructions; the memory-model differences above are checked against the author's documents and with
hand-computed cases.

## How to test

```
GHIDRA_INSTALL_DIR=<Ghidra> PROJ_DIR=<dir whose path has no component starting with '.'> test/run-tests.sh <workdir> [--real]
```
Needs MAME's `unidasm`, SDCC's `ucsim_51` and `sdas8051` (Ubuntu `mame-tools`, `sdcc-ucsim`, `sdcc`); `--real` fetches SDCC 4.5.0 and
two freely licensed sample programs by pinned URL and SHA-256 (nothing is committed). The reference tools are used as black boxes.
`test/r2import_test.py` (PyGhidra) runs the r2 importer script.

## Results

| Area | Result |
|---|---|
| Decode | 427,680 slots (every opcode x every second byte x 5 third bytes, plus 100,000 random 3-byte slots) against MAME `unidasm -arch i8051`: 426,021 agree, 1,659 both invalid (opcode `A5`), **0 differences**. The module's disassembly re-assembled with SDCC's `sdas8051`: 399,252 give the original bytes, 0 differ, 0 fail to assemble; 26,769 AJMP/ACALL left to unidasm (sdas resolves their page bits only at link time). Display: a direct address 0-7 is shown as `R0`-`R7` and direct 0xE0 as `A` (the memory-mapped bank / accumulator, as upstream prints them) |
| Reached | 178/178 constructors reached by the corpus |
| Semantics | 60 hand-computed emulator cases (ADD/ADDC/SUBB flags CY/AC/OV, MUL, DIV incl. by zero, DA, logic without PSW side effects, rotates, every addressing mode incl. the R0-R7/INTMEM aliasing through `@Ri` and direct addresses, MOVC @A+DPTR/@A+PC, MOVX @DPTR and @Ri at page 0x50, MOV SP + PUSH, POP into the register bank, bit instructions on internal RAM, ACC, B and PSW bits, parity, DJNZ/CJNE/JZ/JNZ/SJMP, LCALL/RET, ACALL/AJMP page arithmetic, JMP @A+DPTR, RET/RETI) plus 2 deliberately wrong expectations that are detected; the `xpage` context register (default and a changed value) is checked. 15,262 random single instructions (60 per opcode, random A, B, PSW, SP, DPTR, all 256 bytes of internal RAM and the external memory windows): uCsim's final state equals the module's p-code result in **15,262/15,262**, and a wrong expectation is detected |
| Real code | SDCC 4.5.0-built images placed at the ROM address 0x8000: tiny-AES-c (Unlicense) and B-Con SHA-256 (public domain) in the medium and large models, a test program (`test/real/demo.c`) in all three models, and all of SDCC's library sources (C and assembler) linked in 12 groups; 19 images, 78,971 instructions, 1,289 functions. Against SDCC's own linked listings: all 53,906 listed instructions disassembled with the same length (64 never reached by flow: NOP padding of SDCC's atomic helpers, a second RET), 0 missing; text against unidasm at the same addresses 52,723 agree, 0 differ. 0 bad-instruction or error bookmarks, 795 functions decompiled with 0 failures. (Ghidra also disassembles the NOP padding behind the boot-vector entry points and SDCC's prebuilt start-up code, which has no listing) |
| Doesn't work | see below |
| Unverified | see below |

Spec files: `si4440.cspec` (global ranges RAM, INTMEM, SFR, BITS; the stock 8051 prototype), `si4440.pspec` (vectors, SFR names,
memory blocks, volatile ranges, `xpage` default). No ELF opinion or `.dwarf` map: EZRadioPRO firmware is a raw memory dump and SDCC
writes no ELF/DWARF for the 8051; import a 64 KB dump raw at address 0 with the language selected.

Also tested: the semantic part of the suite (the hand-computed cases, the `xpage` check and 5,088 random instructions) on Ghidra
12.1.3 and 12.2 with 0 failures; the release zips build for 12.1.3, 12.1.4 and 12.2; `r2import.py`
imports the repository's r2 scripts under PyGhidra on 12.1.4 (`test/r2import_test.py`; 704 functions, 69 flags and 1,840 comments
from `radare2/rom-c2a-a2a.r2`).

## Confirmed reference-tool behaviour

- `unidasm -arch i8051` agrees with the module on every encoding tested (no bug found).
- `sdas8051` (SDCC 4.5.0) leaves the page bits of `AJMP` / `ACALL` to the linker (its listing shows the unrelocated opcode), so these
  two are not part of the assembler round trip (unidasm and two hand-computed cases cover them). Not a bug.
- MAME's unidasm, SDCC 4.5.0's listings and uCsim: no decode error found.
- uCsim 0.8.15's 8051 simulator and the commonly documented operation text of `PUSH` / `POP` disagree about `PUSH SP` (the manual
  increments SP, then stores the direct byte, so SP+1 would be stored; uCsim stores the old SP) and `POP SP` (manual: store, then
  decrement; uCsim ends with SP = the popped value). The module follows the manual text. Which one real silicon does is not known here;
  no program uses it. The random tests exclude these two forms.

## Doesn't work (and why)

- Only register bank 0 exists in the model: R0-R7 are INTMEM 0-7 and `PSW.RS0/RS1` select nothing. This is the upstream design
  (the author found one memory-mapped bank in the firmware); a bank chosen at run time cannot be a fixed varnode, and keeping R0-R7
  as named varnodes is what gives readable decompiler output. Code that switches banks is analysed with bank-0 registers. The random
  tests drop the 38 of 15,300 cases whose instruction writes RS0/RS1.
- Peripherals (SPI/DMA engine, packet handler, timers, the modem DSP, interrupts) are not modelled: SFRs and the XREG range are
  volatile locations, interrupts are not raised. Hardware state, not expressible in a processor module.
- `PSW.P` (parity) is computed when PSW is read (direct 0xD0 or a PSW bit), not stored after every ACC change: equivalent for every
  instruction, but a memory view of PSW in the emulator shows a stale bit 0 between reads.
- `DIV AB` by zero leaves A and B unchanged (the chip leaves them undefined; OV is set as documented).
- The compiler spec is upstream's (the stock 8051 one: arguments in ACC, DPTR, B, R0-R7, result in ACC). SDCC passes the first
  argument and returns results in DPL/DPH/B/A, so SDCC-built functions decompile with register "parameters" named after R0-R7;
  the original firmware's compiler is not known, so no other convention was added.

## Unverified

- **Real EZRadioPRO firmware**: no Si4440/EZRadioPRO firmware image was available (the upstream repository deliberately contains
  none, Silicon Labs does not publish them, and no freely licensed dump exists). The memory map, the vector entry points, the XPAGE
  default and the volatile ranges rest on the upstream author's documentation only; real code was tested with SDCC-built programs.
- `PUSH SP` / `POP SP` (see above), and whether the core implements anything at the reserved opcode `A5`.
- `ghidra/EZRadioPROimport.py` and `ghidra/EFR32registers.py` need Silicon Labs tools (`NewWDS.exe`, the RAIL radio configurator)
  that are not redistributable: not run (both compile as Python 3; `r2import.py` was run under PyGhidra 3.1.0 on Ghidra 12.1.4).
- Other EZRadioPRO revisions (B1B parts: NVM at 0xC000, 16 KB ROM): the language has the C2A/A2A memory map only.
