#!/usr/bin/env bash
# Builds a Magisk module that adds ONE certificate to Android's system CA store, so apps
# that don't trust user-installed CAs will trust it. This is for auditing YOUR OWN rooted
# device (phase 8, docs/DECRYPTION.md): the certificate is the one your own TLS proxy
# (e.g. mitmproxy) presents, and the module only exists on your phone.
#
# It does not touch TLS, Traffic AL or any app; it only places a file. Certificate pinning
# is unaffected — pinned apps stay opaque. Only run it with a CA you generated yourself.
#
#   tools/decryption/system-ca.sh <ca-cert.pem> [out-dir]
#
# Then flash out-dir/system-ca-magisk.zip in the Magisk app and reboot.
set -euo pipefail

CERT=${1:?usage: system-ca.sh <ca-cert.pem> [out-dir]}
OUT=${2:-$(mktemp -d)}
MODULE="$OUT/module"
CACERTS="$MODULE/system/etc/security/cacerts"

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
# Android looks up a CA by the old-style subject hash, in a file "<hash>.0".
HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CERT" -noout)
[[ -n "$HASH" ]] || { echo "could not read a certificate from $CERT" >&2; exit 1; }

rm -rf "$MODULE"
mkdir -p "$CACERTS"
# The system store keeps the PEM certificate followed by its text form.
openssl x509 -inform PEM -in "$CERT" -out "$CACERTS/$HASH.0"
openssl x509 -inform PEM -in "$CERT" -text -fingerprint -noout >> "$CACERTS/$HASH.0"

cat > "$MODULE/module.prop" <<EOF
id=trafficaluserca
name=Traffic AL system CA ($HASH)
version=1.0
versionCode=1
author=device owner
description=Adds one self-generated CA to the system trust store for auditing this device.
EOF

# Mount the files over the read-only system partition (Magisk magic mount).
cat > "$MODULE/service.sh" <<'EOF'
#!/system/bin/sh
chmod 644 /data/adb/modules/trafficaluserca/system/etc/security/cacerts/*.0 2>/dev/null
EOF
chmod 755 "$MODULE/service.sh"

ZIP="$OUT/system-ca-magisk.zip"
rm -f "$ZIP"
( cd "$MODULE" && zip -q -r "$ZIP" . )
echo "certificate hash: $HASH"
echo "Magisk module:    $ZIP"
echo "Flash it in the Magisk app and reboot. Remove it there to undo."
