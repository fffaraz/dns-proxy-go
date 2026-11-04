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
		{name: "defaults", want: config{Port: 53}},
		{name: "configured", input: "port = 5300\nblocklist = [\"ads.txt\", \"trackers.txt\"]", want: config{Port: 5300, Blocklist: []string{"ads.txt", "trackers.txt"}}},
		{name: "empty blocklist", input: "blocklist = []", want: config{Port: 53, Blocklist: []string{}}},
		{name: "domain age", input: "min_domain_age_days = 30\nwhois_db_path = \"cache.sqlite\"", want: config{Port: 53, MinDomainAgeDays: 30, WhoisDBPath: "cache.sqlite"}},
		{name: "disabled domain age", input: "min_domain_age_days = 0", want: config{Port: 53}},
		{name: "negative domain age", input: "min_domain_age_days = -1", wantErr: true},
		{name: "wrong domain age type", input: "min_domain_age_days = \"30\"", wantErr: true},
		{name: "wrong WHOIS path type", input: "whois_db_path = 1", wantErr: true},
		{name: "invalid TOML", input: "port = [", wantErr: true},
		{name: "wrong port type", input: "port = \"5300\"", wantErr: true},
		{name: "wrong blocklist type", input: "blocklist = \"ads.txt\"", wantErr: true},
		{name: "unknown key", input: "blocklists = []", wantErr: true},
		{name: "zero port", input: "port = 0", wantErr: true},
		{name: "negative port", input: "port = -1", wantErr: true},
		{name: "port too large", input: "port = 65536", wantErr: true},
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
