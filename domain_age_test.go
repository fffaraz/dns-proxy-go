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

func TestDomainAgeDNSResponses(t *testing.T) {
	previousFilter, previousBlocklist := ageFilter, blocklist.Load()
	t.Cleanup(func() { ageFilter = previousFilter; blocklist.Store(previousBlocklist) })
	for _, tt := range []struct {
		name      string
		proto     string
		listed    bool
		lookupErr error
		want      int
	}{
		{"young UDP", "udp", false, nil, dns.RcodeNameError},
		{"young TCP", "tcp", false, nil, dns.RcodeNameError},
		{"unknown age UDP", "udp", false, errors.New("unavailable"), dns.RcodeServerFailure},
		{"unknown age TCP", "tcp", false, errors.New("unavailable"), dns.RcodeServerFailure},
		{"blocklist first", "udp", true, errors.New("must not look up"), dns.RcodeNameError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ageFilter = testAgeFilter(t, filepath.Join(t.TempDir(), "whois.db"))
			ageFilter.lookup = func(string) (time.Time, error) {
				if tt.listed {
					t.Fatal("blocklisted domain reached WHOIS")
				}
				return time.Now().Add(-24 * time.Hour), tt.lookupErr
			}
			blocklist.Store(nil)
			if tt.listed {
				set := map[string]struct{}{"example.com.": {}}
				blocklist.Store(&set)
			}
			m := new(dns.Msg)
			m.SetQuestion("www.example.com.", dns.TypeA)
			w := new(ageResponseWriter)
			if tt.proto == "tcp" {
				tcpHandler(w, m)
			} else {
				udpHandler(w, m)
			}
			if w.msg == nil || w.msg.Rcode != tt.want || w.msg.Id != m.Id || !w.msg.Response {
				t.Fatalf("DNS response = %v, want rcode %d", w.msg, tt.want)
			}
		})
	}
}
