#!/usr/bin/env bash
set -euo pipefail

# Verify the upstream certificate and print its base64-encoded SHA-256 SPKI pin.
pin=$(
  openssl s_client \
    -connect 1.1.1.2:853 \
    -servername security.cloudflare-dns.com \
    -verify_hostname security.cloudflare-dns.com \
    -verify_return_error </dev/null \
    | openssl x509 -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl base64 -A
)
printf '%s\n' "$pin"
