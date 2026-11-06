#!/usr/bin/env bash
set -euo pipefail

# Run on the machine running Chrome. Extra arguments add hostnames or IPs.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ "$(uname -s)" == Linux ]] && ! command -v certutil >/dev/null 2>&1; then
  printf '%s\n' \
    'certutil is required to install the CA for Chrome on Linux.' \
    'Fedora: sudo dnf install nss-tools' \
    'Debian/Ubuntu: sudo apt install libnss3-tools' >&2
  exit 1
fi

mkcert_bin=mkcert
if ! command -v mkcert >/dev/null 2>&1; then
  if ! command -v go >/dev/null 2>&1; then
    printf '%s\n' 'Go is required to install mkcert automatically. Install Go and rerun this script.' >&2
    exit 1
  fi
  printf '%s\n' 'Installing mkcert with go install...'
  go install filippo.io/mkcert@latest

  # Go's binary directory may not be on PATH. Honor GOBIN and GOPATH defaults.
  mkcert_dir=$(go env GOBIN)
  if [[ -z "$mkcert_dir" ]]; then
    mkcert_gopath=$(go env GOPATH)
    mkcert_dir="${mkcert_gopath%%:*}/bin"
  fi
  mkcert_bin="$mkcert_dir/mkcert"
fi

# mkcert may request administrator privileges to install its local CA.
"$mkcert_bin" -install

umask 077
mkdir -p -- certs
"$mkcert_bin" -cert-file certs/fullchain.pem -key-file certs/privkey.pem \
  localhost 127.0.0.1 ::1 "$@"
chmod 600 certs/privkey.pem

cat <<'EOF'

Certificates are ready. Set these values in config.toml:

self_signed = false
doh_cert_file = "./certs/fullchain.pem"
doh_key_file = "./certs/privkey.pem"

For Docker, add this entry under volumes in compose.yaml:

      - ./certs:/certs:ro

Restart the proxy and Chrome. With doh_port = 8080, use this Secure DNS URL:
https://127.0.0.1:8080/dns-query
EOF
