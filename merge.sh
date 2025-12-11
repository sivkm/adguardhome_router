#!/usr/bin/env bash
set -euo pipefail

OUT="consolidated_blocklist.txt"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

URLS=(
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt"
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt"
  "https://small.oisd.nl/domainswild2"
  "https://raw.githubusercontent.com/sivkm/adguardhome_router/refs/heads/main/blocklist.txt"
)

# Domains that must NEVER be allowlisted (exact or any subdomain)
DISALLOWED_ALLOWLIST_DOMAINS=(
  "doubleclick.net"
  "amazon-adsystem.com"
  "adwolf.ru"
  "sellpoint.net"
  "ad.10010.com"
  "ads.tdbank.com"
  "analytics.amplitude.com"
  "appsflyer.com"
  "adjust.com"
  "adrelayer.com"
  "adserver.com"
)

# Temporary files
BLOCK_TMP="$TMP/block_tmp.txt"
ALLOW_TMP="$TMP/allow_tmp.txt"
> "$BLOCK_TMP"
> "$ALLOW_TMP"

echo "[+] Downloading lists..."
for i in "${!URLS[@]}"; do
  curl -L -s "${URLS[$i]}" -o "$TMP/list_$i.txt"
done

# Helper: lowercase
to_lower() {
  # portable lowercasing
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# Helper: check if a domain is disallowed (suffix-match: exact or subdomain)
is_disallowed_domain() {
  local domain
  domain=$(to_lower "$1")
  for bad in "${DISALLOWED_ALLOWLIST_DOMAINS[@]}"; do
    bad=$(to_lower "$bad")
    # If domain == bad or domain ends with .bad then it's disallowed
    if [[ "$domain" == "$bad" ]] || [[ "$domain" == *".${bad}" ]]; then
      return 0
    fi
  done
  return 1
}

# Extract domain from an @@|| allow rule
# Handles things like:
#   @@||example.com^
#   @@||example.com^$script
#   @@||sub.example.com^/path
# Returns domain on stdout, or empty if none extracted
domain_from_allow() {
  local line="$1"
  # Remove leading @@||
  line="${line#@@||}"
  # Remove leading wildcards
  line="${line#*.}"
  # Extract up to first ^ or / or $ or : or ? or whitespace
  local domain
  domain=$(printf '%s' "$line" | sed -E 's/^([^\/\^\$\:\?\s]+).*/\1/')
  # Sanitize: remove any leading/trailing punctuation
  domain=$(printf '%s' "$domain" | sed -E 's/^[^A-Za-z0-9]+//; s/[^A-Za-z0-9]+$//')
  printf '%s' "$domain"
}

# Extract single domain token and validate basic domain characters
# Returns domain on stdout if token looks like a domain; otherwise empty.
domain_from_token() {
  local token="$1"
  # remove any surrounding punctuation
  token=$(printf '%s' "$token" | sed -E 's/^[^A-Za-z0-9*]+//; s/[^A-Za-z0-9*-]+$//')
  # drop leading wildcard
  token="${token#*.}"
  # Basic domain validation: letters, digits, hyphen, dot (no spaces)
  if [[ "$token" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$ ]]; then
    printf '%s' "$token"
  else
    # Not a domain-looking token
    return 1
  fi
}

echo "[+] Processing lists..."

for FILE in "$TMP"/list_*.txt; do
  while IFS= read -r LINE || [[ -n "$LINE" ]]; do
    # Strip CRLF and trim whitespace
    CLEAN=$(printf '%s' "$LINE" | tr -d '\r' | sed 's/^[ \t]*//;s/[ \t]*$//')
    # Skip empty lines
    [[ -z "$CLEAN" ]] && continue
    # Skip pure comment lines starting with # or !
    if [[ "$CLEAN" == \#* ]] || [[ "$CLEAN" == '!'* ]]; then
      continue
    fi

    # Remove inline comments: anything after unescaped '#'
    # (Simple approach: remove everything after first '#')
    CLEAN="${CLEAN%%#*}"
    # Trim again
    CLEAN=$(printf '%s' "$CLEAN" | sed 's/[ \t]*$//;s/^[ \t]*//')
    [[ -z "$CLEAN" ]] && continue

    # Allowlist entry (prefix @@||)
    if [[ "$CLEAN" == @@\|\|* ]]; then
      # Extract domain
      DOMAIN=$(domain_from_allow "$CLEAN" || true)
      DOMAIN=$(to_lower "$DOMAIN")
      # If domain couldn't be extracted, skip the malformed allow rule
      [[ -z "$DOMAIN" ]] && continue
      # If domain is disallowed (exact or subdomain), drop it
      if is_disallowed_domain "$DOMAIN"; then
        # skip
        continue
      fi
      # Otherwise preserve the original allow rule (normalized)
      echo "$CLEAN" >> "$ALLOW_TMP"
      continue
    fi

    # OISD raw domain file: domainswild2 (these are raw domain lines)
    if [[ "$FILE" == *"domainswild2"* ]]; then
      # Remove inline comments already done above; now accept simple domain tokens only
      TOKEN=$(domain_from_token "$CLEAN" || true) || TOKEN=""
      if [[ -n "$TOKEN" ]]; then
        echo "||$(to_lower "$TOKEN")^" >> "$BLOCK_TMP"
      fi
      continue
    fi

    # Already AdGuard block style (||domain^ or regexp-like)
    if [[ "$CLEAN" == \|\|* ]]; then
      # Keep as-is (but normalize to lowercase domain portion if possible)
      # We'll not attempt to rewrite complex rules; just append the line
      echo "$CLEAN" >> "$BLOCK_TMP"
      continue
    fi

    # Host-file style: IPv4 or IPv6 with one or more domains
    # Split into tokens
    # Example: "0.0.0.0 domain.com domain2.com"
    # Example: "::1 domain.com"
    read -r -a TOKENS <<<"$CLEAN" || TOKENS=()
    if [[ ${#TOKENS[@]} -ge 2 ]]; then
      # First token may be IP. Basic IPv4 check:
      if [[ "${TOKENS[0]}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ "${TOKENS[0]}" =~ ^([0-9A-Fa-f:]+)$ ]]; then
        # Process remaining tokens as domain candidates
        for ((i=1; i<${#TOKENS[@]}; i++)); do
          tok="${TOKENS[i]}"
          # Strip possible inline comment fragments (though already removed)
          tok="${tok%%#*}"
          token_domain=$(domain_from_token "$tok" || true) || token_domain=""
          if [[ -n "$token_domain" ]]; then
            echo "||$(to_lower "$token_domain")^" >> "$BLOCK_TMP"
          fi
        done
        continue
      fi
    fi

    # Raw domain in non-OISD list → convert if token looks like a domain
    TOKEN=$(domain_from_token "$CLEAN" || true) || TOKEN=""
    if [[ -n "$TOKEN" ]]; then
      echo "||$(to_lower "$TOKEN")^" >> "$BLOCK_TMP"
      continue
    fi

    # If we reach here, the line didn't match any known format; skip it.
  done < "$FILE"
done

echo "[+] Sorting and deduplicating..."

# Sort block entries (unique)
sort -u "$BLOCK_TMP" > "$TMP/block_sorted.txt" || true

# Sort allowlist entries (unique)
sort -u "$ALLOW_TMP" > "$TMP/allow_sorted.txt" || true

echo "[+] Writing output to $OUT"

{
  cat "$TMP/block_sorted.txt"
  echo ""
  echo "# Allowlist appended"
  cat "$TMP/allow_sorted.txt"
} > "$OUT"

echo "[+] Done. Output: $OUT"
