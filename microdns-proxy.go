package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
)

const (
	upstreamAddr       = "1.1.1.2:853"
	upstreamServerName = "security.cloudflare-dns.com"
	// base64(sha256(SubjectPublicKeyInfo)) of the upstream leaf certificate.
	upstreamSPKIPin = "ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew="
)

var upstreamTLSConfig = &tls.Config{
	ServerName:            upstreamServerName,
	MinVersion:            tls.VersionTLS13,
	VerifyPeerCertificate: verifyPin,
}

type dnsExchanger interface {
	Exchange(*dns.Msg, string) (*dns.Msg, time.Duration, error)
}

var client dnsExchanger = &dns.Client{
	Net:       "tcp-tls",
	TLSConfig: upstreamTLSConfig,
}

// blocklist holds the current set of blocked FQDNs (lowercase, trailing dot).
// It is nil when no blocklist is configured.
var blocklist atomic.Pointer[map[string]struct{}]

// Initialized before the DNS listeners start; nil disables age filtering.
var ageFilter *domainAgeFilter

type config struct {
	DNSPort          int      `toml:"dns_port"`
	Blocklist        []string `toml:"blocklist"`
	MinDomainAgeDays int      `toml:"min_domain_age_days"`
	WhoisDBPath      string   `toml:"whois_db_path"`
	DoHPort          int      `toml:"doh_port"`
	DoHCertFile      string   `toml:"doh_cert_file"`
	DoHKeyFile       string   `toml:"doh_key_file"`
}

func loadConfig(path string) (config, error) {
	cfg := config{DNSPort: 5300}
	metadata, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return cfg, err
	}
	if keys := metadata.Undecoded(); len(keys) > 0 {
		return cfg, fmt.Errorf("unknown config keys: %v", keys)
	}
	if cfg.DNSPort < 1 || cfg.DNSPort > 65535 {
		return cfg, fmt.Errorf("dns_port must be between 1 and 65535")
	}
	if cfg.DoHPort < 0 || cfg.DoHPort > 65535 {
		return cfg, fmt.Errorf("doh_port must be between 1 and 65535, or 0 to disable DoH")
	}
	if cfg.MinDomainAgeDays < 0 {
		return cfg, fmt.Errorf("min_domain_age_days must be nonnegative")
	}
	if (cfg.DoHCertFile == "") != (cfg.DoHKeyFile == "") {
		return cfg, fmt.Errorf("doh_cert_file and doh_key_file must be configured together")
	}
	if cfg.DoHPort == 0 && cfg.DoHCertFile != "" {
		return cfg, fmt.Errorf("doh_port is required when configuring DoH certificates")
	}
	return cfg, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [config-path]\nConfig path defaults to ./config.toml.\n", os.Args[0])
	}
	flag.Parse()
	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(2)
	}
	configPath := "./config.toml"
	if flag.NArg() == 1 {
		configPath = flag.Arg(0)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config %s: %s", configPath, err)
	}
	addr := ":" + strconv.Itoa(cfg.DNSPort)
	blocklistPaths := cfg.Blocklist

	if len(blocklistPaths) > 0 {
		if err := loadBlocklists(blocklistPaths); err != nil {
			log.Fatalf("Failed to load blocklist: %s\n", err)
		}
	}
	ageFilter, err = openDomainAgeFilter(cfg)
	if err != nil {
		log.Fatalf("Failed to open WHOIS cache: %s", err)
	}
	if ageFilter != nil {
		defer ageFilter.db.Close()
		log.Printf("Domain age filtering enabled: domains must be older than %d days", cfg.MinDomainAgeDays)
	}
	if cfg.DoHPort != 0 {
		srv := newDoHServer(cfg)
		defer srv.Close()
		go func() {
			var err error
			if cfg.DoHCertFile != "" {
				err = srv.ListenAndServeTLS(cfg.DoHCertFile, cfg.DoHKeyFile)
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Failed to start DoH listener: %s", err)
			}
		}()
		scheme := "http"
		if cfg.DoHCertFile != "" {
			scheme = "https"
		}
		log.Printf("Listening on %s://%s/dns-query", scheme, srv.Addr)
	}

	go func() {
		srv := &dns.Server{Addr: addr, Net: "udp4", Handler: dns.HandlerFunc(udpHandler)}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()
	go func() {
		srv := &dns.Server{Addr: addr, Net: "tcp4", Handler: dns.HandlerFunc(tcpHandler)}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to set tcp listener %s\n", err.Error())
		}
	}()
	log.Printf("Listening on %s (udp/tcp), forwarding to %s over TLS\n", addr, upstreamAddr)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s != syscall.SIGHUP {
			log.Printf("Signal (%d) received, stopping\n", s)
			return
		}
		if len(blocklistPaths) == 0 {
			log.Println("SIGHUP received, but no blocklist configured")
			continue
		}
		if err := loadBlocklists(blocklistPaths); err != nil {
			log.Printf("Failed to reload blocklist, keeping the previous one: %s\n", err)
		}
	}
}

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

func verifyPin(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("no peer certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	want, err := base64.StdEncoding.DecodeString(upstreamSPKIPin)
	if err != nil {
		return err
	}
	got := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if !bytes.Equal(got[:], want) {
		return fmt.Errorf("certificate pin mismatch: got %s", base64.StdEncoding.EncodeToString(got[:]))
	}
	return nil
}

func dnsHandler(w dns.ResponseWriter, m *dns.Msg, proto string) {
	w.WriteMsg(resolveDNS(m, proto, w.RemoteAddr().String()))
}

// resolveDNS applies the same filtering and upstream policy to every transport.
func resolveDNS(m *dns.Msg, proto, remoteAddr string) *dns.Msg {
	start := time.Now()
	host, _, _ := net.SplitHostPort(remoteAddr)
	if len(m.Question) != 1 {
		log.Printf("[%s] %s rejected query with %d questions\n", proto, host, len(m.Question))
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeFormatError)
		return r
	}
	q := m.Question[0]
	if isBlocked(q.Name) {
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeNameError)
		log.Printf("[%s] %s %s %s BLOCKED %s\n", proto, host, dns.TypeToString[q.Qtype], q.Name,
			time.Since(start).Round(time.Microsecond))
		return r
	}
	r, _, err := client.Exchange(m, upstreamAddr)
	if err != nil {
		log.Printf("[%s] Upstream exchange failed: %s\n", proto, err)
		r = new(dns.Msg)
		r.SetRcode(m, dns.RcodeServerFailure)
	} else if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		// Check age only after DNS confirms an answer, avoiding WHOIS for
		// nonexistent names, empty answers, and upstream failures.
		blocked, err := ageFilter.isBlocked(q.Name, time.Now())
		if err != nil {
			log.Printf("[%s] %s %s %s WHOIS check failed: %s", proto, host, dns.TypeToString[q.Qtype], q.Name, err)
			r = new(dns.Msg)
			r.SetRcode(m, dns.RcodeServerFailure)
		} else if blocked {
			r = new(dns.Msg)
			r.SetRcode(m, dns.RcodeNameError)
			log.Printf("[%s] %s %s %s BLOCKED (domain age) %s", proto, host, dns.TypeToString[q.Qtype], q.Name,
				time.Since(start).Round(time.Microsecond))
			return r
		}
	}
	if proto == "udp" {
		size := dns.MinMsgSize
		if opt := m.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		r.Truncate(size)
	}
	elapsed := time.Since(start).Round(time.Millisecond)
	truncated := ""
	if r.Truncated {
		truncated = " TRUNCATED"
	}
	log.Printf("[%s] %s %s %s %s%s %s\n", proto, host, dns.TypeToString[q.Qtype], q.Name,
		dns.RcodeToString[r.Rcode], truncated, elapsed)
	return r
}

func udpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "udp")
}

func tcpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "tcp")
}
