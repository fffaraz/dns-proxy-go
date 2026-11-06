package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testAgeFilter(t *testing.T, path string) *domainAgeFilter {
	t.Helper()
	f, err := openDomainAgeFilter(config{MinDomainAgeDays: 30, WhoisDBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Close() })
	return f
}

func TestDomainAgeDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whois.db")
	f, err := openDomainAgeFilter(config{WhoisDBPath: path})
	if err != nil || f != nil {
		t.Fatalf("disabled filter = %v, %v", f, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("disabled filter created a database: %v", err)
	}
	if blocked, err := f.isBlocked("example.com.", time.Now()); blocked || err != nil {
		t.Fatalf("disabled check = %v, %v", blocked, err)
	}
}

func TestDomainAgeInvalidDBPath(t *testing.T) {
	if _, err := openDomainAgeFilter(config{MinDomainAgeDays: 30, WhoisDBPath: t.TempDir()}); err == nil {
		t.Fatal("expected database open error")
	}
}

func TestRegisteredDomain(t *testing.T) {
	for _, tt := range []struct{ name, want string }{
		{"WWW.Example.COM.", "example.com"},
		{"a.b.example.co.uk.", "example.co.uk"},
		{"_sip._tcp.example.com.", "example.com"},
		{"foo.github.io.", "github.io"},
		{"foo.blogspot.com.", "blogspot.com"},
		{"www.xn--bcher-kva.de.", "xn--bcher-kva.de"},
		{"localhost.", ""},
		{"printer.local.", ""},
		{"test.invalid.", ""},
		{"com.", ""},
		{"co.uk.", ""},
		{".", ""},
		{"1.0.0.127.in-addr.arpa.", ""},
		{"b.a.9.8.ip6.arpa.", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := registeredDomain(tt.name)
			if err != nil || got != tt.want {
				t.Fatalf("registeredDomain(%q) = %q, %v; want %q", tt.name, got, err, tt.want)
			}
		})
	}
	if _, err := registeredDomain("bad\\010name.com."); err == nil {
		t.Fatal("expected invalid registered domain to be rejected")
	}
}

func TestDomainAgeBoundaries(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name    string
		age     time.Duration
		blocked bool
	}{
		{"new", 0, true},
		{"young", 29 * 24 * time.Hour, true},
		{"at threshold", 30 * 24 * time.Hour, true},
		{"just old enough", 30*24*time.Hour + time.Nanosecond, false},
		{"old", 365 * 24 * time.Hour, false},
		{"future date", -24 * time.Hour, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := testAgeFilter(t, filepath.Join(t.TempDir(), "whois.db"))
			f.lookup = func(string) (time.Time, error) { return now.Add(-tt.age), nil }
			blocked, err := f.isBlocked("example.com.", now)
			if err != nil || blocked != tt.blocked {
				t.Fatalf("age check = %v, %v; want %v", blocked, err, tt.blocked)
			}
		})
	}
}

func TestDomainAgeCachePersistsAndAges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whois.db")
	f := testAgeFilter(t, path)
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	created := now.Add(-29 * 24 * time.Hour)
	calls := 0
	f.lookup = func(domain string) (time.Time, error) {
		calls++
		if domain != "example.co.uk" {
			t.Fatalf("looked up %q", domain)
		}
		return created, nil
	}
	for _, name := range []string{"www.EXAMPLE.co.uk.", "mail.example.co.uk."} {
		if blocked, err := f.isBlocked(name, now); !blocked || err != nil {
			t.Fatalf("young check = %v, %v", blocked, err)
		}
	}
	if calls != 1 {
		t.Fatalf("WHOIS calls = %d, want 1", calls)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f = testAgeFilter(t, path)
	f.lookup = func(string) (time.Time, error) {
		t.Fatal("WHOIS called for a persistent cache hit")
		return time.Time{}, nil
	}
	if blocked, err := f.isBlocked("example.co.uk.", now.Add(2*24*time.Hour)); blocked || err != nil {
		t.Fatalf("aged cached check = %v, %v", blocked, err)
	}
	var name, date string
	if err := f.db.QueryRow("SELECT name, creation_date FROM domains").Scan(&name, &date); err != nil {
		t.Fatal(err)
	}
	if name != "example.co.uk" || date != created.Format(time.RFC3339Nano) {
		t.Fatalf("unexpected cached row: %q, %q", name, date)
	}
}

func TestDomainAgeConcurrentMisses(t *testing.T) {
	f := testAgeFilter(t, filepath.Join(t.TempDir(), "whois.db"))
	now := time.Now()
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	f.lookup = func(string) (time.Time, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return now.Add(-365 * 24 * time.Hour), nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			if blocked, err := f.isBlocked("www.example.com.", now); blocked || err != nil {
				t.Errorf("concurrent check = %v, %v", blocked, err)
			}
		})
	}
	<-started
	close(release)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("WHOIS calls = %d, want 1", got)
	}
}

func TestDomainAgeLookupFailuresNotCached(t *testing.T) {
	for _, lookupErr := range []error{errors.New("WHOIS unavailable"), nil} {
		f := testAgeFilter(t, filepath.Join(t.TempDir(), "whois.db"))
		calls := 0
		f.lookup = func(string) (time.Time, error) {
			calls++
			return time.Time{}, lookupErr
		}
		for i := 0; i < 2; i++ {
			if _, err := f.isBlocked("example.com.", time.Now()); err == nil {
				t.Fatal("expected lookup/missing date error")
			}
		}
		var count int
		if err := f.db.QueryRow("SELECT COUNT(*) FROM domains").Scan(&count); err != nil || count != 0 || calls != 2 {
			t.Fatalf("failed lookups cached: count=%d, calls=%d, err=%v", count, calls, err)
		}
	}
}

func TestDomainAgeCacheErrors(t *testing.T) {
	f := testAgeFilter(t, filepath.Join(t.TempDir(), "whois.db"))
	f.lookup = func(string) (time.Time, error) {
		t.Fatal("WHOIS must not mask a database error")
		return time.Time{}, nil
	}
	if _, err := f.db.Exec("INSERT INTO domains VALUES ('example.com', 'invalid')"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.isBlocked("example.com.", time.Now()); err == nil {
		t.Fatal("expected invalid cached date error")
	}
	f.db.Close()
	if _, err := f.isBlocked("example.com.", time.Now()); err == nil {
		t.Fatal("expected closed database error")
	}
}

func TestDomainAgeCacheWriteFailure(t *testing.T) {
	f := testAgeFilter(t, filepath.Join(t.TempDir(), "whois.db"))
	f.lookup = func(string) (time.Time, error) {
		return time.Now().Add(-365 * 24 * time.Hour), nil
	}
	if _, err := f.db.Exec("PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.isBlocked("example.com.", time.Now()); err == nil {
		t.Fatal("expected cache write failure to prevent allowing the domain")
	}
}

func TestParseCreationDate(t *testing.T) {
	for _, tt := range []struct {
		name, raw string
		wantErr   bool
	}{
		{"valid", "Domain Name: EXAMPLE.COM\nCreation Date: 1995-08-14T04:00:00Z\n", false},
		{"missing", "Domain Name: EXAMPLE.COM\nUpdated Date: 2026-01-01T00:00:00Z\n", true},
		{"malformed date", "Domain Name: EXAMPLE.COM\nCreation Date: garbage\n", true},
		{"rate limited", "WHOIS query limit exceeded", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCreationDate(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parse error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got.Format(time.RFC3339) != "1995-08-14T04:00:00Z" {
				t.Fatalf("creation date = %v", got)
			}
		})
	}
}

type ageResponseWriter struct{ msg *dns.Msg }

func (w *ageResponseWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *ageResponseWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (w *ageResponseWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *ageResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *ageResponseWriter) Close() error                { return nil }
func (w *ageResponseWriter) TsigStatus() error           { return nil }
func (w *ageResponseWriter) TsigTimersOnly(bool)         {}
func (w *ageResponseWriter) Hijack()                     {}

type dnsExchangeFunc func(*dns.Msg, string) (*dns.Msg, time.Duration, error)

func (f dnsExchangeFunc) Exchange(m *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	return f(m, addr)
}

func TestDomainAgeDNSResponses(t *testing.T) {
	previousFilter, previousBlocklist, previousClient := ageFilter, blocklist.Load(), client
	t.Cleanup(func() {
		ageFilter = previousFilter
		blocklist.Store(previousBlocklist)
		client = previousClient
	})
	for _, proto := range []string{"udp", "tcp", "doh"} {
		for _, tt := range []struct {
			name        string
			listed      bool
			disabled    bool
			rcode       int
			hasAnswer   bool
			dnsErr      error
			age         time.Duration
			lookupErr   error
			want        int
			wantDNS     int
			wantWHOIS   int
			passthrough bool
		}{
			{name: "young", hasAnswer: true, age: 24 * time.Hour, want: dns.RcodeNameError, wantDNS: 1, wantWHOIS: 1},
			{name: "old", hasAnswer: true, age: 365 * 24 * time.Hour, want: dns.RcodeSuccess, wantDNS: 1, wantWHOIS: 1, passthrough: true},
			{name: "unknown age", hasAnswer: true, lookupErr: errors.New("unavailable"), want: dns.RcodeServerFailure, wantDNS: 1, wantWHOIS: 1},
			{name: "nonexistent", rcode: dns.RcodeNameError, want: dns.RcodeNameError, wantDNS: 1, passthrough: true},
			{name: "nonexistent alias target", rcode: dns.RcodeNameError, hasAnswer: true, want: dns.RcodeNameError, wantDNS: 1, passthrough: true},
			{name: "empty answer", want: dns.RcodeSuccess, wantDNS: 1, passthrough: true},
			{name: "upstream SERVFAIL", rcode: dns.RcodeServerFailure, want: dns.RcodeServerFailure, wantDNS: 1, passthrough: true},
			{name: "upstream REFUSED", rcode: dns.RcodeRefused, want: dns.RcodeRefused, wantDNS: 1, passthrough: true},
			{name: "upstream timeout", dnsErr: errors.New("timeout"), want: dns.RcodeServerFailure, wantDNS: 1},
			{name: "disabled", disabled: true, hasAnswer: true, want: dns.RcodeSuccess, wantDNS: 1, passthrough: true},
			{name: "blocklist first", listed: true, want: dns.RcodeNameError},
		} {
			t.Run(proto+"/"+tt.name, func(t *testing.T) {
				dnsCalls, whoisCalls := 0, 0
				ageFilter = testAgeFilter(t, filepath.Join(t.TempDir(), "whois.db"))
				ageFilter.lookup = func(string) (time.Time, error) {
					whoisCalls++
					if dnsCalls != 1 {
						t.Fatal("WHOIS ran before the upstream DNS query")
					}
					return time.Now().Add(-tt.age), tt.lookupErr
				}
				if tt.wantWHOIS == 0 {
					// Even a broken cache must not affect negative DNS responses.
					ageFilter.db.Close()
				}
				if tt.disabled {
					ageFilter = nil
				}
				blocklist.Store(nil)
				if tt.listed {
					set := map[string]struct{}{"example.com.": {}}
					blocklist.Store(&set)
				}
				m := new(dns.Msg)
				m.SetQuestion("www.example.com.", dns.TypeA)
				var upstreamResponse *dns.Msg
				client = dnsExchangeFunc(func(query *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
					dnsCalls++
					if query != m || addr != upstreamAddr {
						t.Fatal("unexpected upstream query or address")
					}
					if tt.dnsErr != nil {
						return nil, 0, tt.dnsErr
					}
					upstreamResponse = new(dns.Msg)
					upstreamResponse.SetRcode(query, tt.rcode)
					if tt.hasAnswer {
						if tt.rcode == dns.RcodeNameError {
							upstreamResponse.Answer = []dns.RR{&dns.CNAME{
								Hdr:    dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
								Target: "missing.example.net.",
							}}
						} else {
							upstreamResponse.Answer = []dns.RR{&dns.A{
								Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
								A:   net.ParseIP("192.0.2.1"),
							}}
						}
					}
					return upstreamResponse, 0, nil
				})
				w := new(ageResponseWriter)
				switch proto {
				case "tcp":
					tcpHandler(w, m)
				case "udp":
					udpHandler(w, m)
				case "doh":
					dnsHandler(w, m, proto)
				}
				if w.msg == nil || w.msg.Rcode != tt.want || w.msg.Id != m.Id || !w.msg.Response {
					t.Fatalf("DNS response = %v, want rcode %d", w.msg, tt.want)
				}
				if dnsCalls != tt.wantDNS || whoisCalls != tt.wantWHOIS {
					t.Fatalf("DNS/WHOIS calls = %d/%d, want %d/%d", dnsCalls, whoisCalls, tt.wantDNS, tt.wantWHOIS)
				}
				if tt.passthrough {
					if w.msg != upstreamResponse {
						t.Fatal("upstream response was replaced")
					}
				} else if len(w.msg.Answer) != 0 {
					t.Fatal("blocked/failed response retained upstream answers")
				}
			})
		}
	}
}
