#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
mkdir -p -- blocklists

download_dir=$(mktemp -d "$PWD/blocklists/.download.XXXXXX")
trap 'rm -rf -- "$download_dir"' EXIT

curl --fail --location --show-error --retry 3 \
  --output "$download_dir/stevenblack.txt" \
  https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
curl --fail --location --show-error --retry 3 \
  --output "$download_dir/hagezi-multi.txt" \
  https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt

# Replace existing lists only after both downloads succeed.
chmod 644 "$download_dir/stevenblack.txt" "$download_dir/hagezi-multi.txt"
mv -- "$download_dir/stevenblack.txt" blocklists/stevenblack.txt
mv -- "$download_dir/hagezi-multi.txt" blocklists/hagezi-multi.txt
