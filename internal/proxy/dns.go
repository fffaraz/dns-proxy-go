package proxy

import (
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Initialized before the DNS listeners start; nil disables age filtering.
var ageFilter *domainAgeFilter

func blockedResponse(m *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(m, dns.RcodeNameError)
	// RFC 2308: negative caching uses the smaller of the SOA TTL and MINIMUM.
	r.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{
			Name: m.Question[0].Name, Rrtype: dns.TypeSOA, Class: m.Question[0].Qclass, Ttl: 0,
		},
		Ns:     ".",
		Mbox:   ".",
		Minttl: 0,
	}}
	return r
}

func dnsHandler(w dns.ResponseWriter, m *dns.Msg, proto string) {
	w.WriteMsg(resolveDNS(m, proto, w.RemoteAddr().String()))
}

// resolveDNS applies the same filtering and upstream policy to every transport.
func resolveDNS(m *dns.Msg, proto, remoteAddr string) *dns.Msg {
	start := time.Now()
	host, _, _ := net.SplitHostPort(remoteAddr)
	if len(m.Question) != 1 {
		log.Printf("[%s] %s rejected query with %d questions\n", proto, host, len(m.Question))
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeFormatError)
		return r
	}
	q := m.Question[0]
	if isBlocked(q.Name) {
		r := blockedResponse(m)
		log.Printf("[%s] %s %s %s BLOCKED %s\n", proto, host, dns.TypeToString[q.Qtype], q.Name,
			time.Since(start).Round(time.Microsecond))
		return r
	}
	r, _, err := client.Exchange(m, upstreamAddr)
	if err != nil {
		log.Printf("[%s] Upstream exchange failed: %s\n", proto, err)
		r = new(dns.Msg)
		r.SetRcode(m, dns.RcodeServerFailure)
	} else if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		// Check age only after DNS confirms an answer, avoiding WHOIS for
		// nonexistent names, empty answers, and upstream failures.
		blocked, err := ageFilter.isBlocked(q.Name, time.Now())
		if err != nil {
			log.Printf("[%s] %s %s %s WHOIS check failed: %s", proto, host, dns.TypeToString[q.Qtype], q.Name, err)
			r = new(dns.Msg)
			r.SetRcode(m, dns.RcodeServerFailure)
		} else if blocked {
			r = blockedResponse(m)
			log.Printf("[%s] %s %s %s BLOCKED (domain age) %s", proto, host, dns.TypeToString[q.Qtype], q.Name,
				time.Since(start).Round(time.Microsecond))
			return r
		}
	}
	if proto == "udp" {
		size := dns.MinMsgSize
		if opt := m.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		r.Truncate(size)
	}
	elapsed := time.Since(start).Round(time.Millisecond)
	rcode := ""
	if r.Rcode != dns.RcodeSuccess {
		rcode = " " + dns.RcodeToString[r.Rcode]
	}
	truncated := ""
	if r.Truncated {
		truncated = " TRUNCATED"
	}
	log.Printf("[%s] %s %s %s%s%s %s\n", proto, host, dns.TypeToString[q.Qtype], q.Name,
		rcode, truncated, elapsed)
	return r
}

func udpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "udp")
}

func tcpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "tcp")
}
