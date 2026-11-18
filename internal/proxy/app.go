package proxy

import (
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/miekg/dns"
)

// Run starts the proxy using the configuration at configPath and waits for signals.
func Run(configPath string) {
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
		srv, err := newDoHServer(cfg)
		if err != nil {
			log.Fatalf("Failed to configure DoH listener: %s", err)
		}
		defer srv.Close()
		go func() {
			var err error
			if cfg.SelfSigned || cfg.DoHCertFile != "" {
				err = srv.ListenAndServeTLS(cfg.DoHCertFile, cfg.DoHKeyFile)
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Failed to start DoH listener: %s", err)
			}
		}()
		scheme := "http"
		if cfg.SelfSigned || cfg.DoHCertFile != "" {
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
