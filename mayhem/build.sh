#!/usr/bin/env bash
#
# mayhem/build.sh — build the ccan fuzz harnesses and the module test suite.
#
# ccan is a collection of small modules under ccan/<mod>/ (no library archive upstream). We
# generate config.h with upstream's own configurator (as its Makefile does), then compile every
# module's .c files twice, out of tree under mayhem/build/ (gitignored):
#   san/  with $SANITIZER_FLAGS $DEBUG_FLAGS  -> libccan.a linked into every fuzz harness
#   norm/ with the project's normal flags     -> libccan.a linked into the upstream test/run*.c
#                                                programs that mayhem/test.sh runs
# Modules excluded are the ones upstream's Makefile excludes (external deps) plus
# coroutine/generator (need ucontext, which config.h does not detect here), daemon_with_notify (duplicate `daemonize` symbol with ccan/daemonize) and failtest.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=$(cd "$(dirname "$0")/.." && pwd)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"
mkdir -p "$B"

# 1) config.h via upstream's configurator (probes the compiler; plain flags).
make -s quiet=1 CC="$CC" CFLAGS= tools/configurator/configurator config.h

# Module sources (same selection rule as upstream's Makefile).
EXCLUDE='^ccan/(altstack|jmap|jset|ogg_to_pcm|tal/talloc|wwviaudio|coroutine|generator|daemon_with_notify|failtest)/'
# A module is a directory with an _info file; its sources are that directory's *.c.
mapfile -t SRCS < <(for i in ccan/*/_info ccan/*/*/_info; do ls "$(dirname "$i")"/*.c 2>/dev/null || true; done \
  | grep -Ev "$EXCLUDE" | LC_ALL=C sort)

# build_lib <dir> <cflags...>: compile each module source to <dir>/<path>.o and archive them.
build_lib() {
  local dir="$1"; shift
  mkdir -p "$dir"
  printf '%s\n' "${SRCS[@]}" | xargs -P "$MAYHEM_JOBS" -I{} sh -c '
    o="$0/$(echo {} | tr / _).o"
    $CC -I. "$@" -c {} -o "$o"' "$dir" "$@"
  rm -f "$dir/libccan.a"
  ar rcs "$dir/libccan.a" "$dir"/*.o
}

# 2) Sanitized, DWARF-3 library + harnesses (fuzzer and standalone reproducer).
# UBSan relaxations (ASan and the rest of UBSan stay halting):
#  - function:  ccan's typesafe_cb pattern calls every callback (tal destructors, opt
#               show/set callbacks, rune checks) through a void*-typed pointer by design; it
#               fires on the first callback of every input.
#  - alignment: crypto/sha256 reads 32-bit words from unaligned input on x86 by design
#               (HAVE_UNALIGNED_ACCESS), hit by every rune parse.
UBSAN_RELAX="-fno-sanitize=function,alignment"
# The module code gets SanitizerCoverage too (not just the harness TU), so the fuzzer sees it.
COV_FLAGS=""
case "$LIB_FUZZING_ENGINE" in *fuzzer*) COV_FLAGS="-fsanitize=fuzzer-no-link" ;; esac
# shellcheck disable=SC2086
build_lib "$B/san" $SANITIZER_FLAGS $UBSAN_RELAX $COV_FLAGS $DEBUG_FLAGS
$CC $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"
mkdir -p "$B/bin"
for h in "$SRC"/mayhem/harnesses/fuzz_*.c; do
  n="$(basename "$h" .c)"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I. "$h" "$B/lsan_off.o" "$B/san/libccan.a" -lm -o "$B/bin/$n"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS -I. "$STANDALONE_FUZZ_MAIN" "$h" "$B/lsan_off.o" "$B/san/libccan.a" -lm -o "$B/bin/$n-standalone"
done

# 3) Test suite with normal flags: upstream's own TAP test programs for the fuzzed modules.
# shellcheck disable=SC2086
build_lib "$B/norm" -O1 -g $COVERAGE_FLAGS
mkdir -p "$B/tests"
: > "$B/tests/list"
while read -r t; do
  [ -n "$t" ] || continue
  n="$(echo "$t" | sed 's,^ccan/,,; s,/test/,__,; s,/,_,g; s,\.c$,,')"
  # shellcheck disable=SC2086
  extra=()
  # opt's tests share a helper TU (test/utils.c) declared in test/utils.h.
  if grep -q '"utils.h"' "$t" && [ -f "$(dirname "$t")/utils.c" ]; then extra=("$(dirname "$t")/utils.c"); fi
  $CC -O1 -g $COVERAGE_FLAGS -I. "$t" "${extra[@]}" "$B/norm/libccan.a" -lm -o "$B/tests/$n"
  echo "$n $(dirname "$(dirname "$t")")" >> "$B/tests/list"
done < "$SRC/mayhem/tests.txt"
echo "built $(ls "$B"/bin | grep -vc standalone) fuzz targets, $(wc -l < "$B/tests/list") tests"
