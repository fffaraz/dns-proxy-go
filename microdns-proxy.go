package main

import (
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
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	upstreamAddr       = "1.1.1.2:853"
	upstreamServerName = "cloudflare-dns.com"
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

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	port := flag.Int("p", 53, "port to listen on")
	flag.Parse()
	addr := ":" + strconv.Itoa(*port)

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
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%d) received, stopping\n", s)
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
	r, _, err := client.Exchange(m, upstreamAddr)
	if err != nil {
		log.Printf("[%s] Upstream exchange failed: %s\n", proto, err)
		r = new(dns.Msg)
		r.SetRcode(m, dns.RcodeServerFailure)
	}
	w.WriteMsg(r)
	elapsed := time.Since(start).Round(time.Millisecond)
	q := m.Question[0]
	log.Printf("[%s] %s %s %s %s %s\n", proto, host, dns.TypeToString[q.Qtype], q.Name,
		dns.RcodeToString[r.Rcode], elapsed)
}

func udpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "udp")
}

func tcpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "tcp")
}
