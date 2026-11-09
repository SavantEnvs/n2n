#!/usr/bin/env bash
#
# mayhem/build.sh — build n2n's fuzz harnesses and its unit-test programs. Runs in the commit image
# (mayhem/Dockerfile) as `mayhem` in /mayhem; safe to re-run offline and after `git clean -ffdX`.
#
#   * the unit tests (tools/tests-*) are built in the tree with n2n's normal flags, for mayhem/test.sh;
#   * libn2n.a is built again, sanitized and coverage-instrumented, in the gitignored build/fuzz
#     copy of the tracked sources, and linked into each harness (plus a -standalone reproducer).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export CC

cd "$SRC"

HARNESSES="fuzz_wire"

# UBSan checks relaxed because n2n trips them on benign patterns on every packet:
#   alignment   - packet fields are read through casts such as *(uint64_t*)&packet[4] (header_encryption.c,
#                 sn_utils.c, edge_utils.c); x86 handles them and every packet exercises them;
#   shift-base  - (uint8_t << 24) and 1 << 31 promote to int and overflow its sign bit (src/tf.c, src/wire.c,
#                 src/n2n.c); the result is the intended 32-bit pattern and every packet exercises it.
# ASan and every other UBSan check stay on and halting.
RELAX="-fno-sanitize=alignment,shift-base"

# 1) The unit tests, with n2n's normal flags, in the tree.
./autogen.sh
env -u CFLAGS -u LDFLAGS ./configure CC="$CC" CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
make clean >/dev/null 2>&1 || true
make -j"$MAYHEM_JOBS" libn2n.a tools

# 2) libn2n.a with sanitizers and SanCov, in an out-of-tree copy of the tracked sources
#    (build/ is gitignored upstream, so `git clean -ffdX` removes it).
FUZZ="$SRC/build/fuzz"
rm -rf "$FUZZ"
mkdir -p "$FUZZ"
git ls-files -z | tar --null -T - -cf - | tar -xf - -C "$FUZZ"
cp configure "$FUZZ/"
cp include/config.h.in "$FUZZ/include/"
(
    cd "$FUZZ"
    env -u CFLAGS -u LDFLAGS ./configure CC="$CC" \
        CFLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS $RELAX" \
        LDFLAGS="$SANITIZER_FLAGS"
    make -j"$MAYHEM_JOBS" libn2n.a
)
LIBS="$(sed -n 's/^LDLIBS_EXTRA=//p' "$FUZZ/config.mak")"

# 3) Harnesses: each one with the libFuzzer engine, and once more with the run-once standalone driver.
#    lsan_off.c turns leak detection off at build time.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$FUZZ/lsan_off.o"

for h in $HARNESSES; do
    flags="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS $RELAX -I$FUZZ/include -I$FUZZ/src"
    $CC $flags -fsanitize=fuzzer-no-link -c "$SRC/mayhem/$h.c" -o "$FUZZ/$h.o"
    $CC $flags $LIB_FUZZING_ENGINE "$FUZZ/$h.o" "$FUZZ/libn2n.a" "$FUZZ/lsan_off.o" $LIBS -o "/mayhem/$h"
    $CC $flags "$STANDALONE_FUZZ_MAIN" "$FUZZ/$h.o" "$FUZZ/libn2n.a" "$FUZZ/lsan_off.o" $LIBS -o "/mayhem/$h-standalone"
done
