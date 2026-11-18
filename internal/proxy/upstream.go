package proxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

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
