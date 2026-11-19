#!/usr/bin/env bash
#
# mayhem/test.sh — RUN DPDK's own unit tests (app/test, `dpdk-test`, built by mayhem/build.sh in
# .build-test with DPDK's normal flags) for the libraries the fuzz targets cover: bpf (validator,
# interpreter, JIT, ELF, cBPF convert), cfgfile, cmdline, kvargs, net, ip_frag reassembly, argparse,
# ipsec SAD.
# Each autotest asserts known answers and prints "Test OK" / "Test Skipped" / "Test Failed"; a
# test passes only when it exits 0 AND prints "Test OK". exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

TESTS="
  bpf_no_instructions_autotest bpf_exit_only_autotest bpf_no_exit_autotest
  bpf_minimal_working_autotest bpf_add_one_autotest bpf_subtract_one_autotest
  bpf_jump_over_invalid_first_autotest bpf_jump_over_invalid_non_first_autotest
  bpf_load_null_autotest bpf_exec_wrong_nb_prog_arg_autotest bpf_exec_wrong_flags_autotest
  bpf_autotest bpf_stack_alignment_autotest bpf_stack_copy_uint128_autotest
  bpf_stack_sse2_autotest bpf_stack_memcpy_autotest bpf_elf_autotest bpf_convert_autotest
  bpf_xadd32_autotest bpf_xadd64_autotest bpf_xchg32_autotest bpf_xchg64_autotest
  bpf_atomic_imms_autotest bpf_validate_events_autotest bpf_validate_autotest cfgfile_autotest
  cmdline_autotest kvargs_autotest net_ether_autotest net_ipv6_autotest argparse_autotest
  cksum_autotest reassembly_autotest ipsec_sad_autotest
"
RUNNER="$SRC/.build-test/app/dpdk-test"
if [ ! -x "$RUNNER" ]; then
  echo "missing $RUNNER — mayhem/build.sh must build it" >&2
  emit_ctrf "dpdk-test" 0 1 0
  exit 1
fi
# Pin EAL lcore 0 to the first CPU this process may run on (works under any cpuset).
CPU=$(awk '/^Cpus_allowed_list/ {split($2, a, /[,-]/); print a[1]}' /proc/self/status)
EAL_ARGS=(--no-huge -m 256 --no-pci --no-shconf --in-memory --no-telemetry "--lcores=0@${CPU:-0}")
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
passed=0 failed=0 skipped=0
for t in $TESTS; do
  out=$(cd "$TMPD" && DPDK_TEST="$t" timeout 300 "$RUNNER" "${EAL_ARGS[@]}" 2>&1)
  rc=$?
  verdict=$(printf '%s\n' "$out" | grep -E '^Test (OK|Skipped|Failed)' | tail -1)
  if [ "$rc" -eq 0 ] && [ "$verdict" = "Test OK" ]; then
    passed=$((passed + 1)); echo "PASS $t"
  elif [ "$rc" -eq 77 ] && [ "$verdict" = "Test Skipped" ]; then
    skipped=$((skipped + 1)); echo "SKIP $t"
  else
    failed=$((failed + 1)); echo "FAIL $t (rc=$rc, ${verdict:-no verdict})"
    printf '%s\n' "$out" | tail -20
  fi
done
emit_ctrf "dpdk-test" "$passed" "$failed" "$skipped"
