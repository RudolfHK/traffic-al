#!/usr/bin/env bash
# Phase 3 acceptance check on the output of run.sh: converts the captured batches to
# PCAPNG + flows with the Kotlin core and compares them with tshark's conversations.
# Needs a JDK and tshark. Usage: tools/host-test/validate.sh <run.sh WORK dir> [out dir]
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$1
OUT=${2:-$WORK}
mkdir -p "$OUT"

"$HERE/../../gradlew" -q -p "$HERE/../../core" captureReport \
  --args="$WORK/batches.bin $OUT/capture.pcapng $OUT/flows.json"
python3 "$HERE/validate_flows.py" "$OUT/capture.pcapng" "$OUT/flows.json"
