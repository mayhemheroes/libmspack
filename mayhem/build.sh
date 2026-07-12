#!/usr/bin/env bash
#
# libmspack/mayhem/build.sh — build the in-process libFuzzer harnesses (+ standalone reproducers)
# for the SZDD/KWAJ (`msexpand`) and CAB (`cabd`) decompressors, and build the project's OWN
# upstream test suite (test/cabd_test, test/chmd_test, test/kwajd_test) with normal flags so
# mayhem/test.sh is an honest functional oracle.
#
# libmspack is an autotools C library. We do TWO builds from the same source tree:
#   (A) in-tree, NORMAL flags: build the upstream check_PROGRAMS. Their fixture dir is compiled in
#       as -DTEST_FILES=$(abs_srcdir)/test/test_files/<fmt> = /mayhem/libmspack/test/test_files/<fmt>,
#       which is present in the image, so test.sh can run them straight from the build tree.
#   (B) out-of-tree, SANITIZED: configure with $SANITIZER_FLAGS to get an ASan+UBSan libmspack.a that
#       the harnesses link against, so the fuzzed decode paths are instrumented.
#
# Idempotent + air-gapped: autoreconf/configure/make are offline; re-running just re-does incremental
# make. No network fetch at build time.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# SANITIZER_FLAGS uses `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS= yields a
# NO-sanitizer build (natural crash, no ASan report) for the coverage/override image.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC LIB_FUZZING_ENGINE MAYHEM_JOBS

SRCDIR="$SRC/libmspack"
MSPACK_INC="$SRCDIR/mspack"

cd "$SRCDIR"

# Generate ./configure once (idempotent: skip if already generated).
[ -x ./configure ] || ./autogen.sh

# ── (A) SANITIZED out-of-tree (VPATH) build of libmspack.a for the harnesses ─────────
# This VPATH configure MUST run before the in-tree configure below: autoconf refuses a VPATH
# build once the source dir itself has been configured ("source directory already configured").
SAN_BUILD="$SRC/build-san"
mkdir -p "$SAN_BUILD"
cd "$SAN_BUILD"
[ -f Makefile ] || "$SRCDIR/configure" --disable-shared --enable-static \
    CC="$CC" CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
make -j"$MAYHEM_JOBS"
SAN_LIB="$SAN_BUILD/.libs/libmspack.a"
[ -f "$SAN_LIB" ] || { echo "build.sh: sanitized libmspack.a not found at $SAN_LIB" >&2; exit 1; }

# ── (B) NORMAL-flags in-tree build of the upstream test suite ────────────────────────
# Configure in-tree (only if not already configured) then build the three check programs.
cd "$SRCDIR"
[ -f Makefile ] || ./configure --disable-shared
make -j"$MAYHEM_JOBS" test/cabd_test test/chmd_test test/kwajd_test

cd "$SRC"

# ── Harnesses: <target>-fuzz (libFuzzer) + <target>-standalone (single-shot reproducer) ──
build_target() {
    local src="$1" out="$2"
    # libFuzzer target — harness + sanitized library, all instrumented.
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
        -I"$MSPACK_INC" -Imayhem \
        "mayhem/$src" "$SAN_LIB" \
        -o "/mayhem/$out"
    # Standalone reproducer — same harness, LLVM's run-once driver, no libFuzzer runtime.
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS \
        -I"$MSPACK_INC" -Imayhem \
        "$STANDALONE_FUZZ_MAIN" "mayhem/$src" "$SAN_LIB" \
        -o "/mayhem/${out}-standalone"
}

build_target fuzz_msexpand.c msexpand-fuzz
build_target fuzz_cabd.c     cabd-fuzz

echo "build.sh: built msexpand-fuzz, cabd-fuzz (+ -standalone) and the upstream test suite"
