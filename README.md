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
port = 5300
blocklist = ["blocklist.txt"]
min_domain_age_days = 1825 # About 5 years; 0 disables age filtering
whois_db_path = "./data/whois.db"
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

## Run without Docker

Requires Go 1.26.8 or newer. Set `blocklist` to local files (or `[]`) and
`whois_db_path` to `"whois.db"` in your config.

```sh
go build -o microdns-proxy .
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
