package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

const dnsMessageType = "application/dns-message"

func newDoHServer(cfg config) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", dohHandler)
	return &http.Server{
		Addr:              cfg.DoHAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// A maximum-size DNS message needs about 87 KiB when base64url encoded.
		MaxHeaderBytes: 128 << 10,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// dohHandler implements the RFC 8484 DNS wire format for GET and POST.
func dohHandler(w http.ResponseWriter, r *http.Request) {
	// Filtering can change independently of DNS TTLs, so do not cache HTTP replies.
	w.Header().Set("Cache-Control", "no-store")
	var wire []byte
	switch r.Method {
	case http.MethodGet:
		params, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(params["dns"]) != 1 || params.Get("dns") == "" {
			http.Error(w, "expected one base64url dns parameter", http.StatusBadRequest)
			return
		}
		encoded := params.Get("dns")
		if len(encoded) > base64.RawURLEncoding.EncodedLen(dns.MaxMsgSize) {
			http.Error(w, "DNS message too large", http.StatusRequestEntityTooLarge)
			return
		}
		wire, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			http.Error(w, "invalid base64url DNS message", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != dnsMessageType {
			http.Error(w, "expected application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, dns.MaxMsgSize)
		wire, err = io.ReadAll(r.Body)
		if err != nil {
			var sizeErr *http.MaxBytesError
			if errors.As(err, &sizeErr) {
				http.Error(w, "DNS message too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "failed to read DNS message", http.StatusBadRequest)
			}
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := new(dns.Msg)
	if err := query.Unpack(wire); err != nil || query.Response {
		http.Error(w, "invalid DNS query", http.StatusBadRequest)
		return
	}
	response := resolveDNS(query, "doh", r.RemoteAddr)
	wire, err := response.Pack()
	if err != nil || len(wire) > dns.MaxMsgSize {
		log.Printf("[doh] Failed to encode response: %v (size %d)", err, len(wire))
		http.Error(w, "failed to encode DNS response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", dnsMessageType)
	w.Write(wire)
}
