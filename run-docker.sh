#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
mkdir -p -- whois-cache

export LOCAL_UID="$(id -u)"
export LOCAL_GID="$(id -g)"

exec docker compose up -d --build "$@"
