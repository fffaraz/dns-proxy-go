package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/sync/singleflight"
	_ "modernc.org/sqlite"
)

const whoisTimeout = 5 * time.Second

type domainAgeFilter struct {
	db         *sql.DB
	minAgeDays int
	lookup     func(string) (time.Time, error)
	lookups    singleflight.Group
}

func openDomainAgeFilter(cfg config) (*domainAgeFilter, error) {
	if cfg.MinDomainAgeDays <= 0 {
		return nil, nil
	}
	path := cfg.WhoisDBPath
	if path == "" {
		path = "whois.db"
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// Serialize SQLite operations without holding a connection during WHOIS.
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA busy_timeout = 5000"); err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS domains (
			name TEXT PRIMARY KEY NOT NULL,
			creation_date TEXT NOT NULL
		)`)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return &domainAgeFilter{db: db, minAgeDays: cfg.MinDomainAgeDays, lookup: lookupCreationDate}, nil
}

// isBlocked reevaluates age on every query, so a cached young domain eventually
// becomes eligible without another WHOIS lookup. Unknown ages return an error.
func (f *domainAgeFilter) isBlocked(name string, now time.Time) (bool, error) {
	if f == nil {
		return false, nil
	}
	domain, err := registeredDomain(name)
	if err != nil || domain == "" {
		return false, err
	}
	// Coalesce concurrent misses (including queries for different subdomains).
	value, err, _ := f.lookups.Do(domain, func() (any, error) {
		var date string
		err := f.db.QueryRow("SELECT creation_date FROM domains WHERE name = ?", domain).Scan(&date)
		if err == nil {
			created, err := time.Parse(time.RFC3339Nano, date)
			if err != nil || created.IsZero() {
				return nil, fmt.Errorf("invalid cached creation date for %s: %q", domain, date)
			}
			return created, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("read WHOIS cache: %w", err)
		}
		created, err := f.lookup(domain)
		if err != nil {
			return nil, fmt.Errorf("WHOIS %s: %w", domain, err)
		}
		if created.IsZero() {
			return nil, fmt.Errorf("WHOIS %s: missing creation date", domain)
		}
		_, err = f.db.Exec("INSERT INTO domains (name, creation_date) VALUES (?, ?) ON CONFLICT(name) DO NOTHING",
			domain, created.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return nil, fmt.Errorf("write WHOIS cache: %w", err)
		}
		return created, nil
	})
	if err != nil {
		return false, err
	}
	// Compare hours to avoid overflowing a time.Duration for large config values.
	return now.Sub(value.(time.Time)).Hours() <= float64(f.minAgeDays)*24, nil
}

// registeredDomain ignores private PSL entries: foo.github.io is registered as
// github.io. Local names, public suffixes and reverse DNS have no domain age.
func registeredDomain(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "arpa" || strings.HasSuffix(name, ".arpa") {
		return "", nil
	}
	for candidate := name; candidate != ""; {
		suffix, icann := publicsuffix.PublicSuffix(candidate)
		if icann {
			if name == suffix {
				return "", nil
			}
			prefix := strings.TrimSuffix(name, "."+suffix)
			domain := prefix[strings.LastIndexByte(prefix, '.')+1:] + "." + suffix
			return idna.Lookup.ToASCII(domain)
		}
		_, rest, found := strings.Cut(candidate, ".")
		if !found {
			break
		}
		candidate = rest
	}
	return "", nil
}

func lookupCreationDate(domain string) (time.Time, error) {
	// Resolve WHOIS servers over the upstream DoT connection. Using the system
	// resolver would recurse if this proxy is itself the system's DNS resolver.
	dialer := &net.Dialer{
		Timeout: whoisTimeout,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := tls.Dialer{NetDialer: &net.Dialer{Timeout: whoisTimeout}, Config: upstreamTLSConfig}
				return d.DialContext(ctx, "tcp", upstreamAddr)
			},
		},
	}
	raw, err := whois.NewClient().SetDialer(dialer).SetTimeout(whoisTimeout).Whois(domain)
	if err != nil {
		return time.Time{}, err
	}
	return parseCreationDate(raw)
}

func parseCreationDate(raw string) (time.Time, error) {
	info, err := whoisparser.Parse(raw)
	if err != nil {
		return time.Time{}, err
	}
	if info.Domain == nil || info.Domain.CreatedDateInTime == nil || info.Domain.CreatedDateInTime.IsZero() {
		return time.Time{}, errors.New("WHOIS response has no valid creation date")
	}
	return info.Domain.CreatedDateInTime.UTC(), nil
}
