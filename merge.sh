#!/usr/bin/env bash
set -e

OUT="consolidated_blocklist.txt"
TMP=$(mktemp -d)

URLS=(
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt"
  "https://small.oisd.nl/domainswild2"
  "https://raw.githubusercontent.com/sivkm/adguardhome_router/refs/heads/main/blocklist.txt"
)

echo "[+] Downloading lists..."
for i in "${!URLS[@]}"; do
  curl -L -s "${URLS[$i]}" -o "$TMP/list_$i.txt"
done

echo "[+] Merging and cleaning..."
cat "$TMP"/list_*.txt \
  | sed 's/\r//g' \
  | sed 's/#.*//g' \
  | sed 's/^ *//g; s/ *$//g' \
  | grep -E '^[A-Za-z0-9.-]+$' \
  | sort -u \
  | awk '{print "||"$1"^"}' \
  > "$OUT"

echo "[+] Done. Output written to $OUT"
