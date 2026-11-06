package main

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"
)

func TestSelfSignedCertificate(t *testing.T) {
	var previous *x509.Certificate
	for i := 0; i < 2; i++ {
		pair, err := newSelfSignedCertificate()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			t.Fatalf("certificate is not self-signed: %v", err)
		}
		if cert.SerialNumber.Sign() <= 0 {
			t.Error("certificate serial must be positive")
		}
		if time.Until(cert.NotAfter) < 364*24*time.Hour || cert.NotBefore.After(time.Now()) {
			t.Error("certificate must be valid now and for a year")
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
				t.Errorf("verify server certificate for %s: %v", host, err)
			}
		}
		if previous != nil {
			if bytes.Equal(previous.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
				t.Error("certificate generation reused a key")
			}
			if previous.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				t.Error("certificate generation reused a serial")
			}
		}
		previous = cert
	}
}
