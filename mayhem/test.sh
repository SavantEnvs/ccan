#!/usr/bin/env bash
#
# mayhem/test.sh — run upstream's own TAP test programs (ccan/<mod>/test/run*.c) for the fuzzed
# modules, built by mayhem/build.sh with normal flags into mayhem/build/tests/. A test program
# passes only if it exits 0, prints its TAP plan "1..N", and reports N "ok" results with no
# "not ok" (graphql prints "total passed: N" / "total failed: 0" instead) — so a neutered (no-op) binary, which prints nothing, fails.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=$(cd "$(dirname "$0")/.." && pwd)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T="$SRC/mayhem/build/tests"
if [ ! -s "$T/list" ]; then
  echo "test runners missing: run mayhem/build.sh first" >&2
  emit_ctrf "ccan-tap" 0 1
  exit 1
fi

passed=0 failed=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
while read -r n moddir; do
  out="$tmp/$n.out"
  # Upstream runs each module test from the module directory (test data paths are relative).
  (cd "$SRC/$moddir" && "$T/$n") > "$out" 2>&1
  rc=$?
  plan="$(grep -Eo '^1\.\.[0-9]+' "$out" | head -1 | cut -d. -f3)"
  oks="$(grep -Ec '^ok [0-9]+' "$out")"
  bad="$(grep -Ec '^not ok [0-9]+' "$out")"
  # graphql's test prints its own totals instead of TAP.
  gpass="$(sed -n 's/^total passed: \([0-9]*\).*/\1/p' "$out" | head -1)"
  gfail="$(sed -n 's/^total failed: \([0-9]*\).*/\1/p' "$out" | head -1)"
  if [ "$rc" -eq 0 ] && [ -z "$plan" ] && [ "${gpass:-0}" -gt 0 ] && [ "$gfail" = 0 ]; then
    passed=$((passed + 1))
  elif [ "$rc" -eq 0 ] && [ -n "$plan" ] && [ "$plan" -gt 0 ] && [ "$oks" -eq "$plan" ] && [ "$bad" -eq 0 ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL $n (rc=$rc plan=${plan:-none} ok=$oks not_ok=$bad)"
    tail -5 "$out"
  fi
done < "$T/list"
echo "ccan module tests: $passed passed, $failed failed"
emit_ctrf "ccan-tap" "$passed" "$failed"
