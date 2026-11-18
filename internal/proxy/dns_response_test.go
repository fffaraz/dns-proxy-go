package proxy

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func assertBlockedResponseTTL(t *testing.T, response *dns.Msg) {
	t.Helper()
	// Check the values clients actually receive on the wire.
	wire, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(dns.Msg)
	if err := decoded.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Answer) != 0 || len(decoded.Ns) != 1 || len(decoded.Extra) != 0 {
		t.Fatalf("expected only a negative-cache SOA in blocked response: %s", decoded)
	}
	soa, ok := decoded.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("blocked authority record = %T, want SOA", decoded.Ns[0])
	}
	if soa.Hdr.Name != decoded.Question[0].Name || soa.Hdr.Class != decoded.Question[0].Qclass {
		t.Errorf("SOA does not match blocked question: %s", decoded)
	}
	if soa.Hdr.Ttl != 0 || soa.Minttl != 0 {
		t.Errorf("blocked SOA TTL/MINIMUM = %d/%d, want 0/0", soa.Hdr.Ttl, soa.Minttl)
	}
}

func TestDNSResponseSize(t *testing.T) {
	previousClient, previousFilter, previousBlocklist := client, ageFilter, blocklist.Load()
	previousLogOutput := log.Writer()
	t.Cleanup(func() {
		client, ageFilter = previousClient, previousFilter
		blocklist.Store(previousBlocklist)
		log.SetOutput(previousLogOutput)
	})
	ageFilter = nil
	blocklist.Store(nil)

	for _, tt := range []struct {
		name      string
		proto     string
		udpSize   uint16
		answers   int
		limit     int
		truncated bool
	}{
		{"UDP without EDNS", "udp", 0, 12, 512, true},
		{"UDP EDNS below minimum", "udp", 256, 12, 512, true},
		{"UDP EDNS 512", "udp", 512, 12, 512, true},
		{"UDP EDNS 1232", "udp", 1232, 12, 1232, true},
		{"UDP large buffer", "udp", 4096, 12, 4096, false},
		{"UDP small response", "udp", 0, 1, 512, false},
		{"TCP without EDNS", "tcp", 0, 12, 0, false},
		{"TCP small EDNS buffer", "tcp", 512, 12, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			log.SetOutput(&logs)
			query := new(dns.Msg)
			query.SetQuestion("example.test.", dns.TypeTXT)
			if tt.udpSize != 0 {
				query.SetEdns0(tt.udpSize, false)
			}
			client = dnsExchangeFunc(func(m *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
				response := new(dns.Msg)
				response.SetReply(m)
				// The upstream's advertised size must not override the client's limit.
				response.SetEdns0(4096, false)
				for i := 0; i < tt.answers; i++ {
					response.Answer = append(response.Answer, &dns.TXT{
						Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
						Txt: []string{strings.Repeat("x", 180)},
					})
				}
				return response, 0, nil
			})
			w := new(ageResponseWriter)
			dnsHandler(w, query, tt.proto)
			if w.msg == nil {
				t.Fatal("no DNS response")
			}
			if w.msg.Truncated != tt.truncated {
				t.Errorf("TC = %v, want %v", w.msg.Truncated, tt.truncated)
			}
			if got := strings.Contains(logs.String(), " TRUNCATED "); got != tt.truncated {
				t.Errorf("TRUNCATED logged = %v, want %v; log: %s", got, tt.truncated, logs.String())
			}
			wire, err := w.msg.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if tt.limit > 0 && len(wire) > tt.limit {
				t.Errorf("response size = %d, exceeds %d bytes", len(wire), tt.limit)
			}
			if !tt.truncated && len(w.msg.Answer) != tt.answers {
				t.Errorf("answers = %d, want %d", len(w.msg.Answer), tt.answers)
			}
		})
	}
}
