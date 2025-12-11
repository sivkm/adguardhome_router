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
    # Strip CRLF and whitespace
    CLEAN=$(echo "$LINE" | tr -d '\r' | sed 's/^[ \t]*//;s/[ \t]*$//')

    # Skip empty lines
    [[ -z "$CLEAN" ]] && continue

    # Skip comments
    [[ "$CLEAN" == \#* ]] && continue

    # Allowlist entry (prefix @@||)
    if [[ "$CLEAN" == @@\|\|* ]]; then
      echo "$CLEAN" >> "$ALLOW_TMP"
      continue
    fi

    # OISD raw domain (no prefix) -> convert to ||domain^
    if [[ "$FILE" == *"domainswild2"* ]]; then
      # Only process valid domain lines
      if [[ "$CLEAN" =~ ^[A-Za-z0-9.-]+$ ]]; then
        echo "||$CLEAN^" >> "$BLOCK_TMP"
      fi
      continue
    fi

    # Already AdGuard block style (||domain^)
    if [[ "$CLEAN" == \|\|* ]]; then
      echo "$CLEAN" >> "$BLOCK_TMP"
      continue
    fi

    # Raw domain in non-OISD list → convert
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
