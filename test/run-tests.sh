#!/usr/bin/env bash
# Si4440 (EZRadioPRO 8051 variant) module test suite: everything that needs no downloaded inputs.
#
#   GHIDRA_INSTALL_DIR=<Ghidra 12.1.x/12.2> test/run-tests.sh [workdir] [--real]
#
# 1. the spec compiles (.sla well under 16 MB); the module directory is linked into Ghidra/Processors/Si4440 if it is not there
# 2. decode differential against MAME's unidasm (-arch i8051, a black box): every opcode x every second byte x five third bytes
#    plus 100,000 random slots; the module's disassembly re-assembled with SDCC's sdas8051 must give the original bytes
# 3. every SLEIGH constructor is reached by that corpus
# 4. p-code: the xpage context register (XpageCheck.java); 62 hand-computed emulator cases (EmuCheck.java) including two deliberately wrong expectations that must be reported;
#    random single instructions: SDCC's uCsim 8051 simulator's final state (A B PSW SP DPTR, 256 bytes of internal RAM, the
#    external-memory windows, PC) from random states is the expectation for the module's p-code (sem_gen.py + SemCheck.java)
# SEMANTICS_ONLY=1 skips steps 2 and 3.  --real adds step 5: SDCC-built programs (test/real-binaries.sh).
#
# Environment: GHIDRA_INSTALL_DIR, JAVA_HOME (optional), PROJ_DIR (where headless projects are created: the path must not contain
# a component that starts with a dot), JOBS (parallel Ghidra runs, default 4), QUICK=1 (30,000 random slots, 20 semantic tests per
# opcode), UNIDASM (MAME's unidasm), UCSIM_51 (SDCC's ucsim_51), SDAS8051.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
REAL=0
ARGS=()
for a in "$@"; do if [[ $a == --real ]]; then REAL=1; else ARGS+=("$a"); fi; done
W=$(readlink -m "${ARGS[0]:-${TMPDIR:-/tmp}/si4440-tests}")
mkdir -p "$W"
export TMPDIR=$W PROJ_DIR=${PROJ_DIR:-$W} JOBS=${JOBS:-4}
TOOLS=$HOME/.cache/ghidra-rare-scratch/tools
export UCSIM_51=${UCSIM_51:-$(command -v ucsim_51 || echo "$TOOLS/sdcc-root/usr/bin/ucsim_51")}
export SDAS8051=${SDAS8051:-$(command -v sdas8051 || echo "$TOOLS/sdcc-root/usr/bin/sdas8051")}
command -v unidasm >/dev/null || { echo "unidasm (MAME) is needed" >&2; exit 2; }
LANG_ID=8051:BE:24:si4440
fail=0
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/Si4440"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then echo "warning: $P exists and is not this module" >&2; fi

echo "== 1. SLEIGH compiles"
"$GHIDRA_INSTALL_DIR/support/sleigh" "$MOD/data/languages/si4440.slaspec" 2>&1 | grep -E "^ERROR" && exit 1 || true
sz=$(stat -c %s "$MOD/data/languages/si4440.sla")
echo "   si4440.sla: $sz bytes"
((sz < 16 * 1024 * 1024))

RAND=100000; PER=60; [[ -n ${QUICK:-} ]] && { RAND=30000; PER=20; }
python3 "$HERE/gen_corpus.py" "$W/all.bin" $RAND 7
if [[ -z ${SEMANTICS_ONLY:-} ]]; then
echo "== 2. decode differential"
unidasm "$W/all.bin" -arch i8051 > "$W/uni.raw"
"$HERE/decode-corpus.sh" $LANG_ID "$W/all.bin" "$W/gh.txt" 8
echo "   against unidasm"
python3 "$HERE/compare.py" "$W/gh.txt" "$W/uni.raw" --corpus "$W/all.bin" --show 4 | tee "$W/compare.txt" || fail=1
echo "   sdas8051 re-assembles the module's disassembly to the original bytes"
python3 "$HERE/asm_roundtrip.py" "$W/gh.txt" "$W/all.bin" "$W/ok.txt" | tee "$W/roundtrip.txt" || fail=1

echo "== 3. every constructor is reached"
"$HERE/decode-corpus.sh" $LANG_ID "$W/all.bin" "$W/reach.txt" 8 Reach.java
python3 "$HERE/reach_check.py" "$W/reach.txt" "$MOD/data/languages" || fail=1
else
[[ -f $W/gh.txt ]] || { "$HERE/decode-corpus.sh" $LANG_ID "$W/all.bin" "$W/gh.txt" 8; }
fi

echo "== 4. p-code: hand-computed emulator tests"
mkdir -p "$W/emu"
python3 "$HERE/emu_tests.py" "$W/emu"
"$HERE/ghidra-script.sh" raw $LANG_ID "$W/emu/emu.bin" EmuCheck.java "$W/emu/tests.txt" "$W/emu/out.txt"
echo "   $(tail -1 "$W/emu/out.txt")"
grep -q " 0 failed" "$W/emu/out.txt" || { grep ^FAIL "$W/emu/out.txt" | head -20; fail=1; }
grep -q "[1-9][0-9]* broken expectations detected" "$W/emu/out.txt" || { echo "   the deliberately wrong expectations were not detected"; fail=1; }

echo "   MOVX @Ri page from the xpage context register"
python3 - "$W/xpage.bin" <<'PY'
import sys
b = bytearray(65536)
b[0x100] = b[0x200] = 0xf2
open(sys.argv[1], 'wb').write(b)
PY
"$HERE/ghidra-script.sh" raw $LANG_ID "$W/xpage.bin" XpageCheck.java "$W/xpage.out"
tail -2 "$W/xpage.out" | sed 's/^/   /'
grep -q "xpage check passed" "$W/xpage.out" || fail=1

echo "   random single instructions against uCsim"
head -c 65536 /dev/zero > "$W/zero64k.bin"
python3 "$HERE/sem_gen.py" "$W/gh.txt" "$W/sem" $PER 5
rm -rf "$W/sem/chunks"; mkdir "$W/sem/chunks"
split -l 1500 -d "$W/sem/tests.txt" "$W/sem/chunks/c."
ls "$W"/sem/chunks/c.?? | xargs -P "$JOBS" -I{} "$HERE/ghidra-script.sh" raw $LANG_ID "$W/zero64k.bin" SemCheck.java {} {}.out
cat "$W"/sem/chunks/c.??.out | grep -v "^emulator tests" > "$W/sem/all.out"
echo "   $(grep -c ^PASS "$W/sem/all.out") passed, $(grep -c ^FAIL "$W/sem/all.out") failed"
if grep -q ^FAIL "$W/sem/all.out"; then grep ^FAIL "$W/sem/all.out" | head -10 | cut -c1-200; fail=1; fi
# the semantic check can fail: the same tests with one wrong expectation (a flipped byte) must be reported
python3 - "$W/sem/chunks/c.00" "$W/sem/wrong.txt" <<'PY'
import sys
l = open(sys.argv[1]).readline().split(' ')
exp = l[2].split(',')
exp[0] = 'ACC=%x' % ((int(exp[0].split('=')[1], 16) + 1) & 255)
open(sys.argv[2], 'w').write('XFAIL_wrong_acc ' + l[1] + ' ' + ','.join(exp) + '\n')
PY
"$HERE/ghidra-script.sh" raw $LANG_ID "$W/zero64k.bin" SemCheck.java "$W/sem/wrong.txt" "$W/sem/wrong.out"
grep -q " 1 broken expectations detected" "$W/sem/wrong.out" || { echo "   the wrong random-state expectation was not detected"; fail=1; }

if ((REAL)); then
	echo "== 5. real code"
	"$HERE/real-binaries.sh" "$W/real" || fail=1
fi
if ((fail)); then echo "FAILED"; exit 1; fi
echo "all tests passed"
