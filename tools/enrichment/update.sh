#!/usr/bin/env bash
# Downloads the sources of the app's offline enrichment data and rebuilds
# app/src/main/assets/enrichment. Run it now and then (DB-IP Lite is updated monthly).
#
#   tools/enrichment/update.sh
#
# Sources (all on GitHub):
# - DB-IP Lite country and ASN, CC BY 4.0 (https://db-ip.com), mirrored by
#   https://github.com/sapics/ip-location-db
# - AdGuard companiesdb (based on WhoTracks.me), CC BY-SA 4.0,
#   https://github.com/AdguardTeam/companiesdb
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
SOURCE=$(mktemp -d)
trap 'rm -rf "$SOURCE"' EXIT

IP_DB=https://raw.githubusercontent.com/sapics/ip-location-db/main
COMPANIES_DB=https://raw.githubusercontent.com/AdguardTeam/companiesdb/main/dist
for file in dbip-country/dbip-country-ipv4.csv dbip-country/dbip-country-ipv6.csv \
            dbip-asn/dbip-asn-ipv4.csv dbip-asn/dbip-asn-ipv6.csv; do
  curl -fsSL --retry 3 -o "$SOURCE/$(basename "$file")" "$IP_DB/$file"
done
curl -fsSL --retry 3 -o "$SOURCE/trackers.json" "$COMPANIES_DB/trackers.json"
curl -fsSL --retry 3 -o "$SOURCE/companies.json" "$COMPANIES_DB/companies.json"
date -u +%Y-%m-%d > "$SOURCE/fetched.txt"

"$ROOT/gradlew" -q -p "$ROOT/core" buildEnrichment --args="$SOURCE $ROOT/app/src/main/assets/enrichment"
