package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
)

const (
	upstreamAddr       = "1.1.1.1:853"
	upstreamServerName = "cloudflare-dns.com"
	// base64(sha256(SubjectPublicKeyInfo)) of the upstream leaf certificate.
	upstreamSPKIPin = "ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew="
)

var client = &dns.Client{
	Net: "tcp-tls",
	TLSConfig: &tls.Config{
		ServerName:            upstreamServerName,
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: verifyPin,
	},
}

func verifyPin(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	want, err := base64.StdEncoding.DecodeString(upstreamSPKIPin)
	if err != nil {
		return err
	}
	if len(rawCerts) == 0 {
		return errors.New("no peer certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	got := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if !bytes.Equal(got[:], want) {
		return fmt.Errorf("certificate pin mismatch: got %s", base64.StdEncoding.EncodeToString(got[:]))
	}
	return nil
}

func main() {
	handler := dns.HandlerFunc(dnsHandler)
	go func() {
		srv := &dns.Server{Addr: ":53", Net: "udp4", Handler: handler}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()
	go func() {
		srv := &dns.Server{Addr: ":53", Net: "tcp4", Handler: handler}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to set tcp listener %s\n", err.Error())
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%d) received, stopping\n", s)
}

func dnsHandler(w dns.ResponseWriter, m *dns.Msg) {
	if len(m.Question) > 0 {
		fmt.Printf("%s\n", m.Question[0].Name)
	}
	r, _, err := client.Exchange(m, upstreamAddr)
	if err != nil {
		log.Printf("Upstream exchange failed: %s\n", err)
		r = new(dns.Msg)
		r.SetRcode(m, dns.RcodeServerFailure)
	}
	w.WriteMsg(r)
}
