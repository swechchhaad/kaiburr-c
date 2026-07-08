# tests/run_failrate.sh [N]            # all 6 runs, N iterations each (default 10^7)
# tests/run_failrate.sh N ref 6        # just ref kaiburr6
#
# intended for a native x86-64 Linux host
set -eu

N=${1:-10000000}
ONLY_IMPL=${2:-}     # optional: ref | avx2
ONLY_NAME=${3:-}     # optional: 4 | 6 | 8

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
mkdir -p tests/logs tests/bin

REF_SRC="kem.c indcpa.c polyvec.c poly.c ntt.c fn.c reduce.c verify.c fips202.c symmetric-shake.c randombytes.c"
AVX_SRC="kem.c indcpa.c polyvec.c poly.c fq.S shuffle.S ntt.S invntt.S basemul.S consts.c rejsample.c fn.c verify.c fips202.c fips202x4.c symmetric-shake.c keccak4x/KeccakP-1600-times4-SIMD256.c randombytes.c"

build_run() {
  impl=$1; name=$2; k=$3
  [ -n "$ONLY_IMPL" ] && [ "$ONLY_IMPL" != "$impl" ] && return 0
  [ -n "$ONLY_NAME" ] && [ "$ONLY_NAME" != "$name" ] && return 0
  bin="tests/bin/fr_${impl}_${name}"
  log="tests/logs/${impl}_${name}.log"
  echo "building $impl kaiburr$name (K=$k) ..."
  if [ "$impl" = ref ]; then
    ( cd ref  && cc -O3 -DKYBER_K=$k -DNRUNS=$N -I. $REF_SRC ../tests/test_failrate.c -o "../$bin" )
  else
    ( cd avx2 && cc -O3 -march=native -mavx2 -mbmi2 -mpopcnt -DKYBER_K=$k -DNRUNS=$N -I. $AVX_SRC ../tests/test_failrate.c -o "../$bin" )
  fi
  nohup "./$bin" > "$log" 2>&1 &
  echo "  launched pid $!  ->  $log"
}

for spec in "4 7" "6 18" "8 24"; do
  # shellcheck disable=SC2086
  set -- $spec
  build_run ref  "$1" "$2"
  build_run avx2 "$1" "$2"
done

echo
echo "All launched. Track progress with:"
echo "  tail -f tests/logs/*.log            # live stream"
echo "  tail -n1 tests/logs/*.log           # one-line status per run"
echo "  grep -l FAILURE tests/logs/*.log    # any run that hit a failure"
