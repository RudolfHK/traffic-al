#!/usr/bin/env bash
# Acceptance checks on the output of run.sh, with the Kotlin core and tshark:
# - phase 3: the captured batches as PCAPNG + flows, compared with tshark's conversations;
# - phase 5: the same packets as segmented recordings and as UDP live streams (PCAP and
#   PCAPNG) received by tools/udp-receiver.py, read back by tshark.
# Needs a JDK, python3 and tshark. Usage: tools/host-test/validate.sh <run.sh WORK dir> [out dir]
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$1
OUT=${2:-$WORK}
mkdir -p "$OUT"

"$HERE/../../gradlew" -q -p "$HERE/../../core" captureReport \
  --args="$WORK/batches.bin $OUT/capture.pcapng $OUT/flows.json"
python3 "$HERE/validate_flows.py" "$OUT/capture.pcapng" "$OUT/flows.json"

RECEIVER="$HERE/../udp-receiver.py"
python3 "$RECEIVER" -b 127.0.0.1 -p 47001 -w "$OUT/udp.pcap" --idle-exit 5 &
PCAP_RECEIVER=$!
python3 "$RECEIVER" -b 127.0.0.1 -p 47002 -w "$OUT/udp.pcapng" --idle-exit 5 &
PCAPNG_RECEIVER=$!
sleep 1
"$HERE/../../gradlew" -q -p "$HERE/../../core" exportCheck \
  --args="$WORK/batches.bin $OUT 127.0.0.1:47001 127.0.0.1:47002"
wait "$PCAP_RECEIVER" "$PCAPNG_RECEIVER"
python3 "$HERE/validate_export.py" "$OUT"
