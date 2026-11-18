package proxy

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

type config struct {
	DNSPort          int      `toml:"dns_port"`
	Blocklist        []string `toml:"blocklist"`
	MinDomainAgeDays int      `toml:"min_domain_age_days"`
	WhoisDBPath      string   `toml:"whois_db_path"`
	DoHPort          int      `toml:"doh_port"`
	SelfSigned       bool     `toml:"self_signed"`
	DoHCertFile      string   `toml:"doh_cert_file"`
	DoHKeyFile       string   `toml:"doh_key_file"`
}

func loadConfig(path string) (config, error) {
	cfg := config{DNSPort: 5300}
	metadata, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return cfg, err
	}
	if keys := metadata.Undecoded(); len(keys) > 0 {
		return cfg, fmt.Errorf("unknown config keys: %v", keys)
	}
	if cfg.DNSPort < 1 || cfg.DNSPort > 65535 {
		return cfg, fmt.Errorf("dns_port must be between 1 and 65535")
	}
	if cfg.DoHPort < 0 || cfg.DoHPort > 65535 {
		return cfg, fmt.Errorf("doh_port must be between 1 and 65535, or 0 to disable DoH")
	}
	if cfg.MinDomainAgeDays < 0 {
		return cfg, fmt.Errorf("min_domain_age_days must be nonnegative")
	}
	if (cfg.DoHCertFile == "") != (cfg.DoHKeyFile == "") {
		return cfg, fmt.Errorf("doh_cert_file and doh_key_file must be configured together")
	}
	if cfg.SelfSigned && cfg.DoHCertFile != "" {
		return cfg, fmt.Errorf("self_signed cannot be combined with doh_cert_file and doh_key_file")
	}
	if cfg.DoHPort == 0 && (cfg.SelfSigned || cfg.DoHCertFile != "") {
		return cfg, fmt.Errorf("doh_port is required when configuring DoH certificates")
	}
	return cfg, nil
}
