package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

func main() {
	go func() {
		srv := &dns.Server{Addr: ":53", Net: "udp", Handler: dns.HandlerFunc(dnsUdpHandler)}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatal("Failed to set udp listener %s\n", err.Error())
		}
	}()
	go func() {
		srv := &dns.Server{Addr: ":53", Net: "tcp", Handler: dns.HandlerFunc(dnsTcpHandler)}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatal("Failed to set tcp listener %s\n", err.Error())
		}
	}()
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case s := <-sig:
			log.Fatalf("Signal (%d) received, stopping\n", s)
		}
	}
}

func dnsHandler(w dns.ResponseWriter, m *dns.Msg, proto string) {
	fmt.Printf("%s\n", m.Question[0].Name)
	m.Question[0].Name = strings.ToUpper(m.Question[0].Name)
	c := new(dns.Client)
	c.Net = proto
	r, _, _ := c.Exchange(m, "8.8.8.8:53")
	r.Question[0].Name = strings.ToLower(r.Question[0].Name)
	for i := 0; i < len(r.Answer); i++ {
		r.Answer[i].Header().Name = strings.ToLower(r.Answer[i].Header().Name)
	}
	w.WriteMsg(r)
}

func dnsUdpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "udp")
}

func dnsTcpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "tcp")
}
