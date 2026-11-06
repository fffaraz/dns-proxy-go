# dns-proxy-go

DNS proxy with ad/tracker blocklists and domain age filtering.

## Run with Docker

Requires Docker with Compose and Bash. From the project directory:

```sh
./run-docker.sh
```

The proxy listens on port **5300**, with StevenBlack and HaGeZi Multi blocklists
included. Running the script again rebuilds the image and updates the lists.

```sh
dig @127.0.0.1 -p 5300 example.com      # Test DNS
dig @127.0.0.1 -p 5300 example.com +tcp # Test over TCP

docker compose logs -f             # View logs
docker compose restart             # Restart after config changes
docker compose down                # Stop
```

## Configuration

Edit `config.toml`, then restart:

```toml
dns_port = 5300
doh_port = 8080
self_signed = true
blocklist = ["blocklist.txt"]
min_domain_age_days = 1825 # About 5 years; 0 disables age filtering
whois_db_path = "./whois-cache/whois.db"
```

Use `blocklist = []` to disable blocklists. Blocked domains and their subdomains
return NXDOMAIN. Age filtering also blocks young domains; domains with unavailable
WHOIS dates may fail to resolve. WHOIS requires outbound TCP port 43.

For custom blocklists, mount each file in `compose.yaml` and add its container path
to `blocklist`. Plain domains, hosts files, and `||domain^` rules are supported.
After editing list contents, reload without restarting:

```sh
docker compose kill -s HUP
```

If changing the listening port, update the port mappings in `compose.yaml` and
run `./run-docker.sh` again.

## DNS-over-HTTPS

The webserver accepts [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html)
DNS wire-format queries at `/dns-query`: GET with an unpadded base64url `dns`
parameter, or POST with an `application/dns-message` body. Responses use the
same media type. All queries use the same blocklists, domain age filtering,
and TLS upstream as UDP/TCP DNS. HTTP replies are marked `Cache-Control: no-store`
so filtering changes take effect immediately.

The supplied config serves HTTPS on port **8080** with `self_signed = true`.
A fresh private key and self-signed certificate are generated in memory on
every startup; no certificate files are written. The certificate is valid
for one year and covers `localhost`, `127.0.0.1`, and `::1`. It is not trusted
automatically by clients; use `curl -k` for local testing.

To use your own certificate, disable `self_signed` and set both paths:

```toml
doh_port = 8443
self_signed = false
doh_cert_file = "/certs/fullchain.pem"
doh_key_file = "/certs/privkey.pem"
```

For Docker, mount the certificate/key files read-only and add a matching TCP
port mapping (for example `8443:8443`) in `compose.yaml`. The files must be
readable by the container user. Rebuild with `./run-docker.sh` after changing
port mappings. The resulting client URL is `https://your-host:8443/dns-query`
(GET URI template: `https://your-host:8443/dns-query{?dns}`).

Test the local HTTPS listener with a query for `www.example.com`, saving the
binary DNS reply:

```sh
curl -k --fail --header 'Accept: application/dns-message' \
  'https://127.0.0.1:8080/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB' \
  --output response.dns
```

For plain HTTP behind a TLS reverse proxy, set `self_signed = false` and omit
both certificate paths. `self_signed` defaults to `false` when omitted and
cannot be combined with certificate files. Omitting `doh_port` or setting it
to `0` disables the webserver; also disable `self_signed` and omit certificate
paths in that case.

## Run without Docker

Requires Go 1.26.8 or newer. Set `blocklist` to local files (or `[]`).
Both Docker and local runs store the database at `./whois-cache/whois.db`.

```sh
go build -o microdns-proxy .
mkdir -p whois-cache
./microdns-proxy                     # Uses ./config.toml
./microdns-proxy /path/config.toml   # Uses another config
```

## Use as the system resolver

On systems using systemd-resolved, create
`/etc/systemd/resolved.conf.d/microdns-proxy.conf`:

```ini
[Resolve]
DNS=127.0.0.1:5300
Domains=~.
```

```sh
sudo systemctl restart systemd-resolved
resolvectl query example.com
```

To undo, delete that file and restart systemd-resolved.

## Updating the pinned key

If DNS queries fail and logs show `certificate pin mismatch`, the upstream key
may have changed. Run this helper (requires Bash and OpenSSL) to verify the
certificate and print its current pin:

```sh
./get-upstream-pin.sh
```

Replace `upstreamSPKIPin` in `microdns-proxy.go` with the printed value, then
run `./run-docker.sh` to rebuild and restart. For local runs, rebuild the binary
and restart the process.
