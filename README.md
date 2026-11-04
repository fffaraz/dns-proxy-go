# dns-proxy-go
DNS proxy written in Go.

## Run

```sh
go build -o microdns-proxy .
./microdns-proxy                  # reads ./config.toml
./microdns-proxy /path/config.toml # reads a different config file

dig @127.0.0.1 -p 5300 example.com         # test over UDP
dig @127.0.0.1 -p 5300 example.com +tcp    # test over TCP
```

## Configuration

The only CLI argument is an optional TOML config file path, defaulting to
`./config.toml`. The file must exist. The included config listens on port 5300:

```toml
port = 5300
blocklist = []
```

Set `port = 53` to use the standard DNS port (needs root or
CAP_NET_BIND_SERVICE). If omitted, `port` defaults to 53.

## Blocklist

Add file paths to the config; the lists are merged:

```toml
port = 5300
blocklist = ["ads.txt", "trackers.txt"]
```

Relative blocklist paths are resolved from the process working directory.
Omit `blocklist` or use an empty array to disable blocking.

Queries for a listed domain, or any subdomain of it, get NXDOMAIN without
reaching the upstream. The file may mix these line formats, so most published
lists work unchanged (`#` starts a comment):

```
ads.example.com              # plain domain
0.0.0.0 tracker.example.com  # hosts file
||telemetry.example.com^     # adblock style
```

For example, to use the StevenBlack list:

```sh
curl -fsSL -o blocklist.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
```

Send `SIGHUP` to reload the files without restarting (`pkill -HUP microdns-proxy`,
or `docker compose kill -s HUP`). If any file fails to load, the previous list
stays active. SIGHUP reloads the blocklist contents; restart after changing the
config. Docker Compose mounts `config.toml`; add blocklist file mounts as shown
in `compose.yaml` and use their container paths in the config.

## Using it as the system resolver (systemd-resolved)

systemd-resolved already listens on port 53, so run the proxy on another
port (e.g. `port = 5300` in `config.toml`) and have resolved forward to it. Create
`/etc/systemd/resolved.conf.d/microdns-proxy.conf`:

```ini
[Resolve]
DNS=127.0.0.1:5300
Domains=~.
```

`Domains=~.` routes all lookups to this server instead of also querying the
per-interface DNS servers handed out by DHCP/NetworkManager.

```sh
sudo systemctl restart systemd-resolved
resolvectl status | head     # Global should show DNS Servers: 127.0.0.1:5300
resolvectl query example.com
```

To undo, delete the file and restart systemd-resolved.

## Updating the pinned key

The upstream certificate is pinned by the base64-encoded SHA-256 of its
public key (SPKI), stored in `upstreamSPKIPin` in `microdns-proxy.go`. If
Cloudflare rotates its key, every query will return SERVFAIL and the log will
show `certificate pin mismatch: got <new value>`.

To get the current value:

```sh
echo | openssl s_client -connect 1.1.1.2:853 -servername cloudflare-dns.com 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

Check that the certificate is genuine (subject `cloudflare-dns.com`, valid chain),
then put the output in `upstreamSPKIPin` and rebuild.
