#!/usr/bin/env bash
# Real 8051 code for the Si4440 variant: programs built with SDCC, imported into Ghidra (language forced: raw images),
# analysed, decompiled, and compared with SDCC's own linked assembler listings and with MAME's unidasm.
#   test/real-binaries.sh <workdir>
# Fetched by pinned URL and SHA-256 (nothing is committed):
#   SDCC 4.5.0 (Ubuntu packages sdcc, sdcc-libraries: compiler, assembler, library sources)
#   kokke/tiny-AES-c  (Unlicense)         AES-128 ECB/CBC/CTR
#   B-Con/crypto-algorithms (public domain) SHA-256
# plus test/real/demo.c (written for this suite) and the library sources of SDCC itself (GPL-2.0 with the library exception),
# built into one image per memory model.  The images are placed at code address 0x8000 (the boot ROM area of the part), external
# data at 0x6000.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "${1:?workdir}")
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
mkdir -p "$W/dl" "$W/sdcc" "$W/src" "$W/out" "$W/ghidra"
export TMPDIR=$W PROJ_DIR=${PROJ_DIR:-$W/ghidra}
LANG_ID=8051:BE:24:si4440

fetch() { # url sha256 file
	local f="$W/dl/$3"
	[[ -f $f ]] || curl -sL -o "$f" "$1"
	echo "$2  $f" | sha256sum -c --quiet - || { echo "SHA-256 mismatch for $3" >&2; exit 1; }
}
UB=http://archive.ubuntu.com/ubuntu/pool/universe/s/sdcc
fetch "$UB/sdcc_4.5.0+dfsg-4_amd64.deb" fe001b87ed398e8e0707b18b8aa3fbdf65387234f859a76b48a637a6d5a0e5f9 sdcc.deb
fetch "$UB/sdcc-libraries_4.5.0+dfsg-4_all.deb" 1073ff621dc929d4d2741199f8fa608e808c1fed2e2de0bf6baa227fe67619c5 sdcc-libraries.deb
AES=23856752fbd139da0b8ca6e471a13d5bcc99a08d
fetch https://raw.githubusercontent.com/kokke/tiny-AES-c/$AES/aes.c f7f78b44654efd3542b6886923dd05194286807ebcfeb078ea05d21fe901ee9e aes.c
fetch https://raw.githubusercontent.com/kokke/tiny-AES-c/$AES/aes.h 9f74a4de3bd11621ff6e8fb9b352b060f699e6c1c67f81a22d104aacad61a23b aes.h
SHA=cfbde48414baacf51fc7c74f275190881f037d32
fetch https://raw.githubusercontent.com/B-Con/crypto-algorithms/$SHA/sha256.c 4cbc93d30c28cee2a056d6f52cbce6e66ff9450f1d712ee4f59761b9b4486fad sha256.c
fetch https://raw.githubusercontent.com/B-Con/crypto-algorithms/$SHA/sha256.h a946e621775fd8251624e77d19f25407c4b6074ab780027e5797b77c7acf79b5 sha256.h
[[ -x $W/sdcc/usr/bin/sdcc ]] || for d in sdcc sdcc-libraries; do dpkg -x "$W/dl/$d.deb" "$W/sdcc"; done
export PATH=$W/sdcc/usr/bin:$PATH SDCC_HOME=$W/sdcc/usr
LIB=$W/sdcc/usr/share/sdcc/lib/src
CC=(sdcc -mmcs51 --iram-size 256 --std-sdcc99)
LK=(--code-loc 0x8000 --xram-loc 0x6000 --code-size 0x7000)

build() { # name model sources... : compile each source, link, image
	local n=$1 m=$2; shift 2
	local opt=(); [[ $m == large ]] && opt=(--model-large); [[ $m == medium ]] && opt=(--model-medium)
	mkdir -p "$W/out/$n-$m"; cd "$W/out/$n-$m"
	local rels=()
	for s in "$@"; do
		"${CC[@]}" "${opt[@]}" -I"$W/dl" -I"$HERE/real" -c "$s" -o "$(basename "$s" .c).rel" >/dev/null 2>&1
		rels+=("$(basename "$s" .c).rel")
	done
	"${CC[@]}" "${opt[@]}" "${LK[@]}" "${rels[@]}" -o "$n-$m.ihx" >/dev/null 2>&1 || true
	# (a model whose internal RAM cannot hold the program does not link: no image)
	[[ -f $n-$m.ihx ]] && python3 "$HERE/ihx2bin.py" "$n-$m.ihx" "$n-$m.bin" >/dev/null
	cd "$W"
	return 0
}
if [[ ! -f $W/out/.built ]]; then
	cat > "$W/dl/main_aes.c" <<'EOF'
#include "aes.h"
volatile uint8_t out[16];
void main(void) {
    struct AES_ctx ctx;
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t buf[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    uint8_t i;
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, buf);
    AES_ECB_decrypt(&ctx, buf);
    for (i = 0; i < 16; i++) out[i] = buf[i];
    for (;;);
}
EOF
	cat > "$W/dl/main_sha.c" <<'EOF'
#include <string.h>
#include "sha256.h"
volatile BYTE out[32];
void main(void) {
    SHA256_CTX ctx; BYTE h[32]; BYTE i;
    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)"abc", 3);
    sha256_final(&ctx, h);
    for (i = 0; i < 32; i++) out[i] = h[i];
    for (;;);
}
EOF
	for m in small medium large; do
		build aes $m "$W/dl/main_aes.c" "$W/dl/aes.c"
		build sha256 $m "$W/dl/main_sha.c" "$W/dl/sha256.c"
		build demo $m "$HERE/real/demo.c"
	done
	# SDCC's whole library (C and assembler sources), large model, linked in groups of 20 modules (the whole library does not fit
	# into the 256 bytes of internal RAM)
	opt=(--model-large)
	D=$W/out/sdcc-lib; mkdir -p "$D"; cd "$D"
	for f in "$LIB"/*.c; do "${CC[@]}" "${opt[@]}" -c "$f" -I"$LIB" -o "$(basename "$f" .c).rel" >/dev/null 2>&1 || true; done
	for f in "$LIB"/mcs51/*.asm; do cp "$f" .; sdas8051 -plosgff "$(basename "$f")" >/dev/null 2>&1 || true; done
	rm -f _ser.rel
	printf 'void main(void){}\nchar putchar(char c){return c;}\n' > main.c
	"${CC[@]}" "${opt[@]}" -c main.c >/dev/null 2>&1
	ls ./*.rel | grep -v '^./main.rel$' | split -l 20 -d - grp.
	link_group() { # name list-file: link, and if the group does not fit into internal RAM, link its halves separately
		local g=$1 list=$2
		mkdir -p "$W/out/sdcc-lib-$g"
		cp main.rel main.lst "$W/out/sdcc-lib-$g/"; for r in $(cat "$list"); do cp "$r" "${r%.rel}.lst" "$W/out/sdcc-lib-$g/"; done
		(cd "$W/out/sdcc-lib-$g"; "${CC[@]}" "${opt[@]}" "${LK[@]}" ./*.rel -o "sdcc-lib-$g.ihx" >/dev/null 2>&1 || true)
		if [[ -f $W/out/sdcc-lib-$g/sdcc-lib-$g.ihx ]]; then
			python3 "$HERE/ihx2bin.py" "$W/out/sdcc-lib-$g/sdcc-lib-$g.ihx" "$W/out/sdcc-lib-$g/sdcc-lib-$g.bin" >/dev/null
		elif (($(wc -l < "$list") > 1)); then
			rm -rf "$W/out/sdcc-lib-$g"
			split -n l/2 -d "$list" "$list.h"
			link_group "${g}a" "$list.h00"; link_group "${g}b" "$list.h01"
		fi
	}
	for g in grp.??; do link_group "$g" "$g"; done
	cd "$W"
	touch "$W/out/.built"
fi

fail=0
for bin in "$W"/out/*/*.bin; do
	n=$(basename "$bin" .bin); d=$(dirname "$bin")
	[[ -s $bin ]] || continue
	rst=("$d"/*.rst)
	echo "== $n"
	# entry points: the reset vector at the start of the image and every interrupt vector of the part are entries by the
	# language's default symbols; the image is imported raw (there is no loader for it) with the language forced
	# entries: the function symbols of the linker map (a program's functions that nothing calls are not found by flow analysis)
	python3 "$HERE/mk_entries.py" "$d/$n.map" "$W/out/$n.ent" "${rst[@]}"
	"$HERE/ghidra-script.sh" raw $LANG_ID "$bin" RealCheck.java "$W/out/$n.sum" "$W/out/$n.lst" 4000 "$W/out/$n.ent" analyze || { fail=1; continue; }
	grep -E "^(instructions|functions|bookmark|decompiled)" "$W/out/$n.sum" | sed 's/^/   /'
	python3 "$HERE/real_compare.py" "$W/out/$n.lst" "$bin" "${rst[@]}" || fail=1
done
((fail == 0))
