# dns-proxy-go
DNS proxy written in Go.

## Run

```sh
go build -o microdns-proxy .
sudo ./microdns-proxy          # listens on port 53 (needs root or CAP_NET_BIND_SERVICE)
./microdns-proxy -p 5300       # listens on a custom port

dig @127.0.0.1 -p 5300 example.com
```

## Updating the pinned key

The upstream certificate is pinned by the base64-encoded SHA-256 of its
public key (SPKI), stored in `upstreamSPKIPin` in `microdns-proxy.go`. If
Cloudflare rotates its key, every query will return SERVFAIL and the log will
show `certificate pin mismatch: got <new value>`.

To get the current value:

```sh
echo | openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

Check that the certificate is genuine (subject `cloudflare-dns.com`, valid chain),
then put the output in `upstreamSPKIPin` and rebuild.
