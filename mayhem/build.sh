#!/usr/bin/env bash
#
# mayhem/build.sh — build DPDK's fuzz harnesses and the unit-test app (dpdk-test) used by test.sh.
#
# Two meson trees, both in hidden directories (upstream's .gitignore ignores ".*", so
# `git clean -ffdX` removes them):
#   .build-fuzz  static libraries built with $SANITIZER_FLAGS $DEBUG_FLAGS + SanCov
#                (-fsanitize=fuzzer-no-link); the harnesses in mayhem/harnesses link against it
#                through meson's uninstalled pkg-config file.
#   .build-test  the same library set plus app/test (dpdk-test), with DPDK's normal flags.
# Everything resolves from the image (apt: meson, pyelftools, libelf, libpcap, libnuma) — no
# network. Re-running reconfigures the existing trees and rebuilds incrementally.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Libraries the harnesses reach (bpf, cfgfile, kvargs, cmdline, net, ip_frag, gro, acl, ipsec) plus their
# dependencies; the only driver is the ring mempool handler that rte_pktmbuf_pool_create() needs.
LIBS=bpf,cfgfile,kvargs,cmdline,net,ip_frag,hash,rcu,gro,acl,ipsec,security,cryptodev,ethdev,meter,mbuf,mempool,ring,telemetry
COMMON_OPTS=(
  -Ddefault_library=static -Dexamples= -Denable_drivers=mempool/ring
  "-Denable_libs=$LIBS" -Dplatform=generic -Dmax_lcores=128 -Dmax_numa_nodes=1
  -Ddeveloper_mode=disabled -Dwerror=false -Denable_docs=false -Db_lundef=false
)

meson_setup() {  # <builddir> <meson args...>
  local dir="$1"; shift
  if [ -f "$dir/build.ninja" ]; then
    # `meson setup --reconfigure` keeps the old c_args; `meson configure` applies them.
    meson configure "$dir" "$@"
  else
    meson setup "$dir" "$@"
  fi
}

# 1) Sanitized + SanCov-instrumented DPDK libraries for the harnesses.
# UBSan's `alignment` check alone is relaxed: DPDK reads packet headers and eBPF programs read
# their context at arbitrary byte offsets by design (x86 permits unaligned access), and the check
# fired on the first unaligned eBPF load / header within seconds, masking everything else.
# ASan and every other UBSan check stay on and halting.
UBSAN_RELAX="-fno-sanitize=alignment"
FUZZ_CFLAGS="$SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
meson_setup .build-fuzz "${COMMON_OPTS[@]}" -Dtests=false -Ddisable_apps='*' \
  -Dbuildtype=plain -Doptimization=1 -Ddebug=false \
  "-Dc_args=$FUZZ_CFLAGS" "-Dc_link_args=$SANITIZER_FLAGS"
ninja -C .build-fuzz -j"$MAYHEM_JOBS"

# 2) Harnesses: libFuzzer binary + standalone reproducer each.
export PKG_CONFIG_PATH="$SRC/.build-fuzz/meson-uninstalled"
DPDK_CFLAGS=$(pkg-config --cflags libdpdk)
DPDK_LIBS=$(pkg-config --static --libs libdpdk)
OBJ="$SRC/.build-fuzz/mayhem-harness"
mkdir -p "$OBJ"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OBJ/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
# fuzz_bpf_cbpf: rte_bpf_convert()'s length-counting pass advances a NULL output pointer
# (bpf_convert.c `new_insn += 3` with new_insn == NULL) on EVERY input, which halting UBSan
# reports as pointer-overflow before any fuzzing happens. For this one target, bpf_convert.c is
# recompiled with only -fno-sanitize=pointer-overflow (same command meson used, from
# compile_commands.json) and linked in place of the archive member; every other check stays on.
CBPF_DIR="$OBJ/cbpf"
mkdir -p "$CBPF_DIR"
CONVERT_CMD=$(python3 - "$SRC/.build-fuzz/compile_commands.json" <<'PY'
import json, shlex, sys
for e in json.load(open(sys.argv[1])):
    if e["file"].endswith("lib/bpf/bpf_convert.c"):
        a = shlex.split(e["command"])
        out, skip = [], False
        for x in a:
            if skip:
                skip = False
                continue
            if x in ("-MQ", "-MF", "-o"):
                skip = True
                continue
            if x in ("-MD", "-c") or x.endswith("bpf_convert.c"):
                continue
            out.append(x)
        print(shlex.join(out))
        break
PY
)
[ -n "$CONVERT_CMD" ] || { echo "bpf_convert.c not in compile_commands.json" >&2; exit 1; }
# shellcheck disable=SC2086
(cd "$SRC/.build-fuzz" && eval "$CONVERT_CMD -fno-sanitize=pointer-overflow -c ../lib/bpf/bpf_convert.c -o '$CBPF_DIR/bpf_convert.o'")
cp -f "$SRC/.build-fuzz/lib/librte_bpf.a" "$CBPF_DIR/librte_bpf.a"
ar d "$CBPF_DIR/librte_bpf.a" bpf_bpf_convert.c.o

TARGETS="fuzz_bpf_exec fuzz_bpf_jit fuzz_bpf_elf fuzz_bpf_cbpf fuzz_net_ptype fuzz_ip_frag fuzz_gro fuzz_cfgfile fuzz_kvargs fuzz_cmdline fuzz_acl fuzz_ipsec_inb"
for t in $TARGETS; do
  EXTRA=""
  [ "$t" = fuzz_bpf_cbpf ] && EXTRA="-L$CBPF_DIR $CBPF_DIR/bpf_convert.o"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link -D_GNU_SOURCE -DALLOW_EXPERIMENTAL_API \
    $DPDK_CFLAGS -c "$SRC/mayhem/harnesses/$t.c" -o "$OBJ/$t.o"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/$t.o" "$OBJ/lsan_off.o" \
    $EXTRA $DPDK_LIBS -o "$SRC/$t"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/standalone_main.o" "$OBJ/$t.o" "$OBJ/lsan_off.o" \
    $EXTRA $DPDK_LIBS -o "$SRC/$t-standalone"
done

# 3) DPDK's own unit-test app with normal flags (the functional oracle run by mayhem/test.sh).
meson_setup .build-test "${COMMON_OPTS[@]}" -Dtests=true -Denable_apps=test \
  -Dbuildtype=debugoptimized "-Dc_args=$COVERAGE_FLAGS" "-Dc_link_args=$COVERAGE_FLAGS"
ninja -C .build-test -j"$MAYHEM_JOBS" app/dpdk-test
