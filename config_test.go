package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    config
		wantErr bool
	}{
		{name: "defaults", want: config{DNSPort: 53}},
		{name: "configured", input: "dns_port = 5300\nblocklist = [\"ads.txt\", \"trackers.txt\"]", want: config{DNSPort: 5300, Blocklist: []string{"ads.txt", "trackers.txt"}}},
		{name: "empty blocklist", input: "blocklist = []", want: config{DNSPort: 53, Blocklist: []string{}}},
		{name: "domain age", input: "min_domain_age_days = 30\nwhois_db_path = \"cache.sqlite\"", want: config{DNSPort: 53, MinDomainAgeDays: 30, WhoisDBPath: "cache.sqlite"}},
		{name: "disabled domain age", input: "min_domain_age_days = 0", want: config{DNSPort: 53}},
		{name: "DoH HTTP", input: "doh_port = 8080", want: config{DNSPort: 53, DoHPort: 8080}},
		{name: "DoH HTTPS", input: "doh_port = 8443\ndoh_cert_file = \"cert.pem\"\ndoh_key_file = \"key.pem\"", want: config{DNSPort: 53, DoHPort: 8443, DoHCertFile: "cert.pem", DoHKeyFile: "key.pem"}},
		{name: "DoH disabled", input: "doh_port = 0", want: config{DNSPort: 53}},
		{name: "DoH wrong port type", input: "doh_port = \"8080\"", wantErr: true},
		{name: "DoH negative port", input: "doh_port = -1", wantErr: true},
		{name: "DoH port too large", input: "doh_port = 65536", wantErr: true},
		{name: "port boundaries", input: "dns_port = 1\ndoh_port = 65535", want: config{DNSPort: 1, DoHPort: 65535}},
		{name: "DoH certificate only", input: "doh_port = 8443\ndoh_cert_file = \"cert.pem\"", wantErr: true},
		{name: "DoH key only", input: "doh_port = 8443\ndoh_key_file = \"key.pem\"", wantErr: true},
		{name: "DoH TLS without listener", input: "doh_cert_file = \"cert.pem\"\ndoh_key_file = \"key.pem\"", wantErr: true},
		{name: "negative domain age", input: "min_domain_age_days = -1", wantErr: true},
		{name: "wrong domain age type", input: "min_domain_age_days = \"30\"", wantErr: true},
		{name: "wrong WHOIS path type", input: "whois_db_path = 1", wantErr: true},
		{name: "invalid TOML", input: "dns_port = [", wantErr: true},
		{name: "wrong port type", input: "dns_port = \"5300\"", wantErr: true},
		{name: "wrong blocklist type", input: "blocklist = \"ads.txt\"", wantErr: true},
		{name: "unknown key", input: "blocklists = []", wantErr: true},
		{name: "zero port", input: "dns_port = 0", wantErr: true},
		{name: "negative port", input: "dns_port = -1", wantErr: true},
		{name: "port too large", input: "dns_port = 65536", wantErr: true},
		{name: "old DNS key", input: "port = 5300", wantErr: true},
		{name: "old DoH key", input: "doh_addr = \":8080\"", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.input), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := loadConfig(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("loadConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("loadConfig() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := loadConfig(filepath.Join(t.TempDir(), "missing.toml")); !os.IsNotExist(err) {
		t.Fatalf("expected missing file error, got %v", err)
	}
}
