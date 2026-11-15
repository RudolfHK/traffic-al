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

# tshark reads capture files through a privilege-dropped reader, so it must be able to both
# read the file and traverse every directory down to it. The Gradle daemon writes the outputs
# under the runner home with a umask/permissions that block that on the current CI image, so
# make the files world-readable and every ancestor directory world-traversable before a read.
readable() {
  chmod -R a+rX "$OUT" 2>/dev/null || true
  local d="$OUT"
  while [ -n "$d" ] && [ "$d" != "/" ]; do chmod a+x "$d" 2>/dev/null || true; d=$(dirname "$d"); done
}

"$HERE/../../gradlew" -q -p "$HERE/../../core" captureReport \
  --args="$WORK/batches.bin $OUT/capture.pcapng $OUT/flows.json"
readable
{ echo "== host-test diag"; id; tshark --version | head -1; namei -om "$OUT/capture.pcapng"; } || true
python3 "$HERE/validate_flows.py" "$OUT/capture.pcapng" "$OUT/flows.json"

"$HERE/../../gradlew" -q -p "$HERE/../../core" exportCheck --args="$WORK/batches.bin $OUT"
readable
python3 "$HERE/validate_export.py" "$OUT"

# phase 8: the TLS leg's session keys, embedded as a PCAPNG Decryption Secrets Block,
# let tshark decrypt the HTTPS in the capture.
if [[ -s "$WORK/keylog.txt" ]]; then
  "$HERE/../../gradlew" -q -p "$HERE/../../core" decryptCheck \
    --args="$WORK/batches.bin $WORK/keylog.txt $OUT/decrypted.pcapng"
  readable
  python3 "$HERE/validate_decrypt.py" "$OUT/decrypted.pcapng"

  # phase 10: the in-app TLS 1.3 decryptor recovers the HTTP from the same key log.
  "$HERE/../../gradlew" -q -p "$HERE/../../core" tlsDecrypt \
    --args="$WORK/batches.bin $WORK/keylog.txt 8443" > "$OUT/tls-decrypt.txt"
  # Both the TLS 1.3 and the TLS 1.2 leg must come back readable.
  for host in tls.example.test tls12.example.test; do
    if grep -aq "Host: $host" "$OUT/tls-decrypt.txt"; then
      echo "OK: in-app decryption recovered the request to $host"
    else
      echo "FAIL: in-app TLS decryption did not recover the request to $host"; grep -a "connection from port" "$OUT/tls-decrypt.txt"; exit 1
    fi
  done

  # phase 12: the data-flow audit dissects the decrypted request and flags the planted
  # sensitive data (an email in the query and an auth token in the header).
  for kind in EMAIL AUTH; do
    if grep -aq "audit exposure: $kind" "$OUT/tls-decrypt.txt"; then
      echo "OK: the audit flagged $kind in the decrypted request"
    else
      echo "FAIL: the audit did not flag $kind"; grep -a "audit " "$OUT/tls-decrypt.txt"; exit 1
    fi
  done

  # phase 11: the in-app QUIC decryptor recovers the HTTP/3 response from the same key log.
  "$HERE/../../gradlew" -q -p "$HERE/../../core" quicDecrypt \
    --args="$WORK/batches.bin $WORK/keylog.txt 4433" > "$OUT/quic-decrypt.txt" 2>/dev/null || true
  if grep -aq "quic ok /small" "$OUT/quic-decrypt.txt"; then
    echo "OK: in-app QUIC decryption recovered the HTTP/3 response"
  else
    echo "FAIL: in-app QUIC decryption did not recover the response"; grep -a "QUIC connection" "$OUT/quic-decrypt.txt" | head; exit 1
  fi
fi
