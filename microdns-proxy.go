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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	upstreamAddr       = "1.1.1.2:853"
	upstreamServerName = "security.cloudflare-dns.com"
	// base64(sha256(SubjectPublicKeyInfo)) of the upstream leaf certificate.
	upstreamSPKIPin = "ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew="
)

var client = &dns.Client{
	Net: "tcp-tls",
	TLSConfig: &tls.Config{
		ServerName:            upstreamServerName,
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: verifyPin,
	},
}

// blocklist holds the current set of blocked FQDNs (lowercase, trailing dot).
// It is nil when no blocklist is configured.
var blocklist atomic.Pointer[map[string]struct{}]

// stringList is a flag.Value that collects every occurrence of a repeatable flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	port := flag.Int("p", 53, "port to listen on")
	var blocklistPaths stringList
	flag.Var(&blocklistPaths, "blocklist", "file of domains to block (plain, hosts or ||domain^ format); repeatable; reloaded on SIGHUP")
	flag.Parse()
	addr := ":" + strconv.Itoa(*port)

	if len(blocklistPaths) > 0 {
		if err := loadBlocklists(blocklistPaths); err != nil {
			log.Fatalf("Failed to load blocklist: %s\n", err)
		}
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
			log.Fatalf("Signal (%d) received, stopping\n", s)
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
func readBlocklist(path string, set map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
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
	start := time.Now()
	host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	if len(m.Question) != 1 {
		log.Printf("[%s] %s rejected query with %d questions\n", proto, host, len(m.Question))
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeFormatError)
		w.WriteMsg(r)
		return
	}
	q := m.Question[0]
	if isBlocked(q.Name) {
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeNameError)
		w.WriteMsg(r)
		log.Printf("[%s] %s %s %s BLOCKED %s\n", proto, host, dns.TypeToString[q.Qtype], q.Name,
			time.Since(start).Round(time.Microsecond))
		return
	}
	r, _, err := client.Exchange(m, upstreamAddr)
	if err != nil {
		log.Printf("[%s] Upstream exchange failed: %s\n", proto, err)
		r = new(dns.Msg)
		r.SetRcode(m, dns.RcodeServerFailure)
	}
	w.WriteMsg(r)
	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[%s] %s %s %s %s %s\n", proto, host, dns.TypeToString[q.Qtype], q.Name,
		dns.RcodeToString[r.Rcode], elapsed)
}

func udpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "udp")
}

func tcpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "tcp")
}
