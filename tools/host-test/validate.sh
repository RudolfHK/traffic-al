#!/usr/bin/env bash
# Acceptance checks on the output of run.sh, with the Kotlin core and tshark:
# - phase 3: the captured batches as PCAPNG + flows, compared with tshark's conversations;
# - phases 5 and 6: the same packets as segmented recordings (plain, size-limited,
#   encrypted, and encrypted but cut off), exported and read back by tshark.
# Needs a JDK, python3 and tshark. Usage: tools/host-test/validate.sh <run.sh WORK dir> [out dir]
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$1
OUT=${2:-$WORK}
mkdir -p "$OUT"

"$HERE/../../gradlew" -q -p "$HERE/../../core" captureReport \
  --args="$WORK/batches.bin $OUT/capture.pcapng $OUT/flows.json"
python3 "$HERE/validate_flows.py" "$OUT/capture.pcapng" "$OUT/flows.json"

"$HERE/../../gradlew" -q -p "$HERE/../../core" exportCheck --args="$WORK/batches.bin $OUT"
python3 "$HERE/validate_export.py" "$OUT"
