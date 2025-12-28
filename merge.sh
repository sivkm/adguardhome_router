#!/usr/bin/env bash
set -e

OUT="consolidated_blocklist.txt"
TMP=$(mktemp -d)

URLS=(
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt"
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt"
  "https://small.oisd.nl/domainswild2"
  "https://raw.githubusercontent.com/sivkm/adguardhome_router/refs/heads/main/blocklist.txt"
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts"
)

echo "[+] Downloading lists..."
for i in "${!URLS[@]}"; do
  curl -L -s "${URLS[$i]}" -o "$TMP/list_$i.txt"
done

BLOCK_TMP="$TMP/block_tmp.txt"
ALLOW_TMP="$TMP/allow_tmp.txt"

touch "$BLOCK_TMP"
touch "$ALLOW_TMP"

echo "[+] Processing lists..."

for FILE in "$TMP"/list_*.txt; do
  while IFS= read -r LINE || [[ -n "$LINE" ]]; do
    CLEAN=$(echo "$LINE" | tr -d '\r' | sed 's/^[ \t]*//;s/[ \t]*$//')
    [[ -z "$CLEAN" ]] && continue
    [[ "$CLEAN" == \#* ]] && continue

    # Allowlist entry
    if [[ "$CLEAN" == @@\|\|* ]]; then
      echo "$CLEAN" >> "$ALLOW_TMP"
      continue
    fi

    # OISD raw domains
    if [[ "$FILE" == *"domainswild2"* ]]; then
      if [[ "$CLEAN" =~ ^[A-Za-z0-9.-]+$ ]]; then
        echo "||$CLEAN^" >> "$BLOCK_TMP"
      fi
      continue
    fi

    # AdGuard-style block rule
    if [[ "$CLEAN" == \|\|* ]]; then
      echo "$CLEAN" >> "$BLOCK_TMP"
      continue
    fi

    # Host-file: IPv4
    if [[ "$CLEAN" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]+([A-Za-z0-9.-]+)$ ]]; then
      DOMAIN="${BASH_REMATCH[2]}"
      echo "||$DOMAIN^" >> "$BLOCK_TMP"
      continue
    fi

    # Host-file: IPv6
    if [[ "$CLEAN" =~ ^([0-9A-Fa-f:]+)[[:space:]]+([A-Za-z0-9.-]+)$ ]]; then
      DOMAIN="${BASH_REMATCH[2]}"
      echo "||$DOMAIN^" >> "$BLOCK_TMP"
      continue
    fi

    # Raw domain
    if [[ "$CLEAN" =~ ^[A-Za-z0-9.-]+$ ]]; then
      echo "||$CLEAN^" >> "$BLOCK_TMP"
      continue
    fi

  done < "$FILE"
done


echo "[+] Sorting and deduping..."

# Sort block entries
sort -u "$BLOCK_TMP" > "$TMP/block_sorted.txt"

# Sort allowlist entries
sort -u "$ALLOW_TMP" > "$TMP/allow_sorted.txt"

echo "[+] Writing output to $OUT"

{
  cat "$TMP/block_sorted.txt"
  echo ""
  echo "# Allowlist appended"
  cat "$TMP/allow_sorted.txt"
} > "$OUT"

echo "[+] Done."
# updated
