// SPDX-License-Identifier: AGPL-3.0-or-later

// Command siem-collector to agent Vardra w trybie kolektora: odbiera
// syslog z urządzeń (zapory, routery, przełączniki, NAS) i wysyła go do
// serwera tak jak agent Windows – mTLS, paczki, bufor dyskowy na czas
// braku łączności, heartbeat w panelu (Huginn), odnawianie certyfikatu.
// Działa na Linuksie i Windows (np. jako kontener na serwerze Vardra).
//
//	siem-collector enroll -server <adres> -token <token> -ca ca.crt -dir <katalog>
//	siem-collector run -config <katalog>/collector.yaml
//	siem-collector tls-cert -dir <katalog> -host <nazwa lub IP>[,…]
//	siem-collector version
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"siem/agent/internal/hostagent"
	"siem/agent/internal/source"
	"siem/agent/internal/status"
	"siem/agent/internal/syslog"
)

var version = "dev"

// Config to collector.yaml.
type Config struct {
	hostagent.Common `yaml:",inline"`
	Syslog           struct {
		UDP          string   `yaml:"udp"`
		TCP          string   `yaml:"tcp"`
		MaxMessageKB int      `yaml:"max_message_kb"`
		Allow        []string `yaml:"allow"`
		// TLS (RFC 5425): adres nasłuchu, certyfikat kolektora i opcjonalnie
		// CA certyfikatów urządzeń (wtedy certyfikat urządzenia jest wymagany)
		// oraz lista dozwolonych nazw z tych certyfikatów.
		TLS            string   `yaml:"tls"`
		TLSCert        string   `yaml:"tls_cert"`
		TLSKey         string   `yaml:"tls_key"`
		TLSClientCA    string   `yaml:"tls_client_ca"`
		TLSClientNames []string `yaml:"tls_client_names"`
	} `yaml:"syslog"`
}

func loadConfig(path string) (*Config, error) {
	c := &Config{}
	base, err := hostagent.Load(path, c, &c.Common)
	if err != nil {
		return nil, err
	}
	s := &c.Syslog
	s.TLSCert, s.TLSKey, s.TLSClientCA = hostagent.Abs(base, s.TLSCert), hostagent.Abs(base, s.TLSKey), hostagent.Abs(base, s.TLSClientCA)
	switch {
	case s.UDP == "" && s.TCP == "" && s.TLS == "":
		return nil, errors.New("syslog: specify udp, tcp or tls (e.g. \":514\")")
	case s.TLS != "" && (s.TLSCert == "" || s.TLSKey == ""):
		return nil, errors.New("syslog.tls: tls_cert and tls_key are required (siem-collector tls-cert creates them)")
	case s.TLS == "" && (s.TLSClientCA != "" || len(s.TLSClientNames) > 0):
		return nil, errors.New("syslog: tls_client_ca and tls_client_names need tls")
	case len(s.TLSClientNames) > 0 && s.TLSClientCA == "":
		return nil, errors.New("syslog.tls_client_names: needs tls_client_ca")
	}
	return c, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: siem-collector enroll|run|version …")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ExitOnError)
		server := fs.String("server", "", "server (ingest) address, e.g. 192.168.88.98:8443")
		token := fs.String("token", "", "enrollment token from the panel (Bifröst)")
		ca := fs.String("ca", "ca.crt", "server CA certificate")
		panel := fs.String("panel", "", "panel address (default from the server address)")
		dir := fs.String("dir", ".", "collector directory (certificates, collector.yaml, state)")
		_ = fs.Parse(os.Args[2:])
		err = hostagent.Enroll(hostagent.EnrollOptions{Server: *server, Token: *token, CAFile: *ca, Panel: *panel, Dir: *dir,
			OS: "kolektor syslog", Version: version, ConfigName: "collector.yaml", Config: configTemplate})
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		cfgPath := fs.String("config", "collector.yaml", "configuration file")
		_ = fs.Parse(os.Args[2:])
		err = run(*cfgPath)
	case "tls-cert":
		fs := flag.NewFlagSet("tls-cert", flag.ExitOnError)
		dir := fs.String("dir", ".", "collector directory (writes certs/syslog.crt and certs/syslog.key)")
		hosts := fs.String("host", "", "collector names and IP addresses that devices connect to, comma separated")
		days := fs.Int("days", 3650, "validity in days")
		force := fs.Bool("force", false, "overwrite an existing certificate")
		_ = fs.Parse(os.Args[2:])
		err = tlsCert(*dir, *hosts, *days, *force)
	case "version":
		fmt.Println("siem-collector", version)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func configTemplate(serverURL string) string {
	return fmt.Sprintf(`# Kolektor syslog Vardra (siem-collector).
server:
  url: %s
  ca_file: certs/ca.crt
  cert_file: certs/agent.crt
  key_file: certs/agent.key
state_dir: state
syslog:
  udp: ":514"
  tcp: ":514"
  max_message_kb: 64
  # Zalecane: tylko sieci urządzeń (syslog nie ma uwierzytelnienia – bez listy
  # każdy w sieci może podsunąć wiadomości). Puste = wszyscy.
  # allow: ["192.168.88.0/24"]
  # Syslog przez TLS (port 6514). Certyfikat: siem-collector tls-cert -dir <katalog> -host <nazwa/IP>
  # tls: ":6514"
  # tls_cert: certs/syslog.crt
  # tls_key: certs/syslog.key
  # Certyfikat urządzenia wymagany (CA, które go wystawiło) i ew. dozwolone nazwy:
  # tls_client_ca: certs/devices-ca.crt
  # tls_client_names: ["fw1.firma.local"]
buffer:
  max_mb: 2048
  on_full: drop_oldest
`, serverURL)
}

func run(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	var allow []netip.Prefix
	for _, a := range cfg.Syslog.Allow {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return fmt.Errorf("syslog.allow %q: %w", a, err)
		}
		allow = append(allow, p.Masked())
	}
	scfg := syslog.Config{UDP: cfg.Syslog.UDP, TCP: cfg.Syslog.TCP, MaxMessage: cfg.Syslog.MaxMessageKB << 10,
		Allow: allow, TLS: cfg.Syslog.TLS, ClientNames: cfg.Syslog.TLSClientNames}
	if scfg.TLS != "" {
		if scfg.TLSConfig, err = syslog.ServerTLS(cfg.Syslog.TLSCert, cfg.Syslog.TLSKey, cfg.Syslog.TLSClientCA); err != nil {
			return err
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var src *syslog.Source
	return hostagent.Run(hostagent.RunOptions{
		Common: &cfg.Common, Version: version, Mode: "collector", Log: log,
		MaxEventBytes: cfg.Syslog.MaxMessageKB << 10,
		Sources: func(_ string, log *slog.Logger, _ *status.Tracker) ([]source.Source, error) {
			src = &syslog.Source{Cfg: scfg, Log: log}
			log.Info("collector: listening", "udp", cfg.Syslog.UDP, "tcp", cfg.Syslog.TCP, "tls", cfg.Syslog.TLS, "allow", cfg.Syslog.Allow)
			return []source.Source{src}, nil
		},
		Every: func(log *slog.Logger) {
			if src != nil {
				log.Info("syslog: liczniki", "received", src.Stats.Received.Load(), "denied", src.Stats.Denied.Load(),
					"truncated", src.Stats.Truncated.Load(), "refused_tcp", src.Stats.Refused.Load(), "tls_failed", src.Stats.TLSFailed.Load())
			}
		},
	})
}

// tlsCert zapisuje samopodpisany certyfikat odbioru syslog przez TLS.
func tlsCert(dir, hosts string, days int, force bool) error {
	var names []string
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			names = append(names, h)
		}
	}
	certFile, keyFile := filepath.Join(dir, "certs", "syslog.crt"), filepath.Join(dir, "certs", "syslog.key")
	if _, err := os.Stat(certFile); err == nil && !force {
		return fmt.Errorf("%s exists (use -force to replace it – devices must then trust the new one)", certFile)
	}
	certPEM, keyPEM, err := syslog.SelfSigned(names, days)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("Written %s and %s.\nCopy %s to the devices as the trusted CA and set in collector.yaml:\n"+
		"  tls: \":6514\"\n  tls_cert: certs/syslog.crt\n  tls_key: certs/syslog.key\n", certFile, keyFile, certFile)
	return nil
}
