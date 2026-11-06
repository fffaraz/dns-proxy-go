package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func resetDoHState(t *testing.T) {
	t.Helper()
	previousClient, previousFilter, previousBlocklist := client, ageFilter, blocklist.Load()
	t.Cleanup(func() {
		client, ageFilter = previousClient, previousFilter
		blocklist.Store(previousBlocklist)
	})
	ageFilter = nil
	blocklist.Store(nil)
}

func dohQuery(t *testing.T) (*dns.Msg, []byte) {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeTXT)
	query.SetEdns0(512, false)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return query, wire
}

func TestDoHResponses(t *testing.T) {
	resetDoHState(t)
	query, wire := dohQuery(t)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, scenario := range []struct {
			name    string
			rcode   int
			blocked bool
			fail    bool
		}{
			{name: "large answer", rcode: dns.RcodeSuccess},
			{name: "upstream NXDOMAIN", rcode: dns.RcodeNameError},
			{name: "blocked subdomain", rcode: dns.RcodeNameError, blocked: true},
			{name: "upstream failure", rcode: dns.RcodeServerFailure, fail: true},
			{name: "invalid question count", rcode: dns.RcodeFormatError},
		} {
			t.Run(method+"/"+scenario.name, func(t *testing.T) {
				blocklist.Store(nil)
				if scenario.blocked {
					set := map[string]struct{}{"test.": {}}
					blocklist.Store(&set)
				}
				calls := 0
				client = dnsExchangeFunc(func(m *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
					calls++
					if addr != upstreamAddr || m.Id != query.Id || m.Question[0] != query.Question[0] {
						t.Errorf("unexpected upstream query: %s to %s", m, addr)
					}
					if scenario.fail {
						return nil, 0, errors.New("upstream unavailable")
					}
					response := new(dns.Msg)
					response.SetRcode(m, scenario.rcode)
					if scenario.rcode == dns.RcodeSuccess {
						for i := 0; i < 12; i++ {
							response.Answer = append(response.Answer, &dns.TXT{
								Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
								Txt: []string{strings.Repeat("x", 180)},
							})
						}
					}
					return response, 0, nil
				})
				requestWire := wire
				if scenario.rcode == dns.RcodeFormatError {
					invalid := query.Copy()
					invalid.Question = nil
					var err error
					requestWire, err = invalid.Pack()
					if err != nil {
						t.Fatal(err)
					}
				}
				path := "/dns-query"
				if method == http.MethodGet {
					path += "?dns=" + base64.RawURLEncoding.EncodeToString(requestWire)
				}
				req := httptest.NewRequest(method, path, bytes.NewReader(requestWire))
				req.Header.Set("Content-Type", dnsMessageType)
				w := httptest.NewRecorder()
				newDoHServer(config{}).Handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
				}
				if w.Header().Get("Content-Type") != dnsMessageType || w.Header().Get("Cache-Control") != "no-store" {
					t.Errorf("unexpected headers: %v", w.Header())
				}
				response := new(dns.Msg)
				if err := response.Unpack(w.Body.Bytes()); err != nil {
					t.Fatal(err)
				}
				if !response.Response || response.Id != query.Id || response.Rcode != scenario.rcode {
					t.Errorf("unexpected response: %s", response)
				}
				if scenario.rcode == dns.RcodeSuccess && (response.Truncated || len(response.Answer) != 12 || w.Body.Len() <= 512) {
					t.Errorf("DoH must preserve the full response despite EDNS size: %s", response)
				}
				wantCalls := 1
				if scenario.blocked || scenario.rcode == dns.RcodeFormatError {
					wantCalls = 0
				}
				if calls != wantCalls {
					t.Errorf("upstream calls = %d, want %d", calls, wantCalls)
				}
			})
		}
	}
}

func TestDoHInvalidRequests(t *testing.T) {
	resetDoHState(t)
	client = dnsExchangeFunc(func(*dns.Msg, string) (*dns.Msg, time.Duration, error) {
		t.Fatal("invalid request reached the upstream")
		return nil, 0, nil
	})
	query, wire := dohQuery(t)
	query.Response = true
	responseWire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(wire)
	for _, tt := range []struct {
		name, method, path, contentType string
		body                            []byte
		status                          int
	}{
		{name: "missing query", method: "GET", path: "/dns-query", status: 400},
		{name: "empty query", method: "GET", path: "/dns-query?dns=", status: 400},
		{name: "duplicate query", method: "GET", path: "/dns-query?dns=" + encoded + "&dns=" + encoded, status: 400},
		{name: "bad base64", method: "GET", path: "/dns-query?dns=!!!", status: 400},
		{name: "bad URL encoding", method: "GET", path: "/dns-query?dns=%zz", status: 400},
		{name: "bad GET DNS", method: "GET", path: "/dns-query?dns=AAAA", status: 400},
		{name: "large GET", method: "GET", path: "/dns-query?dns=" + strings.Repeat("A", base64.RawURLEncoding.EncodedLen(dns.MaxMsgSize)+1), status: 413},
		{name: "missing content type", method: "POST", path: "/dns-query", body: wire, status: 415},
		{name: "wrong content type", method: "POST", path: "/dns-query", contentType: "application/json", body: wire, status: 415},
		{name: "empty body", method: "POST", path: "/dns-query", contentType: dnsMessageType, status: 400},
		{name: "bad POST DNS", method: "POST", path: "/dns-query", contentType: dnsMessageType, body: []byte("invalid"), status: 400},
		{name: "DNS response", method: "POST", path: "/dns-query", contentType: dnsMessageType, body: responseWire, status: 400},
		{name: "large POST", method: "POST", path: "/dns-query", contentType: dnsMessageType, body: make([]byte, dns.MaxMsgSize+1), status: 413},
		{name: "unsupported method", method: "PUT", path: "/dns-query", status: 405},
		{name: "HEAD", method: "HEAD", path: "/dns-query", status: 405},
		{name: "unknown path", method: "GET", path: "/", status: 404},
		{name: "subpath", method: "GET", path: "/dns-query/other", status: 404},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			w := httptest.NewRecorder()
			newDoHServer(config{}).Handler.ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Errorf("HTTP %d, want %d: %s", w.Code, tt.status, w.Body.String())
			}
			if tt.status == http.StatusMethodNotAllowed && w.Header().Get("Allow") != "GET, POST" {
				t.Errorf("Allow = %q", w.Header().Get("Allow"))
			}
		})
	}
}

func TestDoHOverHTTPS(t *testing.T) {
	resetDoHState(t)
	set := map[string]struct{}{"example.test.": {}}
	blocklist.Store(&set)
	srv := httptest.NewUnstartedServer(newDoHServer(config{}).Handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, wire := dohQuery(t)
	resp, err := srv.Client().Post(srv.URL+"/dns-query", dnsMessageType, bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("unexpected HTTP response: %s %s", resp.Proto, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		t.Fatal(err)
	}
	if response.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN", response.Rcode)
	}
}
