#!/usr/bin/env bash
#
# mayhem/test.sh — run n2n's unit tests (built by mayhem/build.sh). Each program in tests/tests_units.list
# prints known-answer output (hashes, ciphers, key exchange, wire encodings, transform round trips) that
# must match tests/<name>.expected byte for byte, as `make test.units` does.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
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

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

passed=0
failed=0
for t in $(sed -e 's/#.*//' tests/tests_units.list); do
  if [ ! -x "tools/$t" ]; then
    echo "missing tools/$t: mayhem/build.sh did not build it" >&2
    failed=$((failed + 1))
    continue
  fi
  if "tools/$t" > "$out/$t.out" 2> "$out/$t.err" && cmp -s "tests/$t.expected" "$out/$t.out"; then
    echo "PASS $t"
    passed=$((passed + 1))
  else
    echo "FAIL $t"
    diff "tests/$t.expected" "$out/$t.out" | head -n 10
    failed=$((failed + 1))
  fi
done

emit_ctrf "n2n-unit-tests" "$passed" "$failed"
