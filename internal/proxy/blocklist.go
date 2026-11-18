package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// blocklist holds the current set of blocked FQDNs (lowercase, trailing dot).
// It is nil when no blocklist is configured.
var blocklist atomic.Pointer[map[string]struct{}]

// Names that hosts-format lists map to loopback addresses and that must not be blocked.
var hostsBoilerplate = map[string]bool{
	"localhost.": true, "localhost.localdomain.": true, "local.": true, "broadcasthost.": true,
	"ip6-localhost.": true, "ip6-loopback.": true, "ip6-localnet.": true, "ip6-mcastprefix.": true,
	"ip6-allnodes.": true, "ip6-allrouters.": true, "ip6-allhosts.": true,
}

// loadBlocklists reads all paths into one set and atomically replaces the active blocklist.
// If any file fails, the active blocklist is left unchanged.
func loadBlocklists(paths []string) error {
	set := make(map[string]struct{})
	for _, path := range paths {
		before := len(set)
		if err := readBlocklist(path, set); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		log.Printf("Read %d new blocked domains from %s\n", len(set)-before, path)
	}
	blocklist.Store(&set)
	log.Printf("Loaded %d blocked domains from %d file(s)\n", len(set), len(paths))
	return nil
}

// readBlocklist adds the domains in path to set. Each line may be a plain domain,
// a hosts entry ("0.0.0.0 domain ...") or an adblock rule ("||domain^").
// Adblock comments ("!") and bracketed headers are ignored.
func readBlocklist(path string, set map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if net.ParseIP(fields[0]) != nil {
			fields = fields[1:] // hosts format: drop the address
		}
		for _, name := range fields {
			name = strings.TrimSuffix(strings.TrimPrefix(name, "||"), "^")
			name = dns.Fqdn(strings.ToLower(name))
			if _, ok := dns.IsDomainName(name); !ok || name == "." || hostsBoilerplate[name] || net.ParseIP(strings.TrimSuffix(name, ".")) != nil {
				continue
			}
			set[name] = struct{}{}
		}
	}
	return sc.Err()
}

// isBlocked reports whether name or any of its parent domains is in the blocklist.
func isBlocked(name string) bool {
	set := blocklist.Load()
	if set == nil {
		return false
	}
	name = strings.ToLower(name)
	for off, end := 0, false; !end; off, end = dns.NextLabel(name, off) {
		if _, ok := (*set)[name[off:]]; ok {
			return true
		}
	}
	return false
}
