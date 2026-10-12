// Command siem-collector to agent Heimdalla w trybie kolektora: odbiera
// syslog z urządzeń (zapory, routery, przełączniki, NAS) i wysyła go do
// serwera tak jak agent Windows – mTLS, paczki, bufor dyskowy na czas
// braku łączności, heartbeat w panelu (Huginn), odnawianie certyfikatu.
// Działa na Linuksie i Windows (np. jako kontener na serwerze Heimdalla).
//
//	siem-collector enroll -server <adres> -token <token> -ca ca.crt -dir <katalog>
//	siem-collector run -config <katalog>/collector.yaml
//	siem-collector version
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"

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
	} `yaml:"syslog"`
}

func loadConfig(path string) (*Config, error) {
	c := &Config{}
	if _, err := hostagent.Load(path, c, &c.Common); err != nil {
		return nil, err
	}
	if c.Syslog.UDP == "" && c.Syslog.TCP == "" {
		return nil, errors.New("syslog: podaj udp albo tcp (np. \":514\")")
	}
	return c, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "użycie: siem-collector enroll|run|version …")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ExitOnError)
		server := fs.String("server", "", "adres serwera (ingest), np. 192.168.88.98:8443")
		token := fs.String("token", "", "token rejestracyjny z panelu (Bifröst)")
		ca := fs.String("ca", "ca.crt", "certyfikat CA serwera")
		panel := fs.String("panel", "", "adres panelu (domyślnie z adresu serwera)")
		dir := fs.String("dir", ".", "katalog kolektora (certyfikaty, collector.yaml, stan)")
		_ = fs.Parse(os.Args[2:])
		err = hostagent.Enroll(hostagent.EnrollOptions{Server: *server, Token: *token, CAFile: *ca, Panel: *panel, Dir: *dir,
			OS: "kolektor syslog", Version: version, ConfigName: "collector.yaml", Config: configTemplate})
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		cfgPath := fs.String("config", "collector.yaml", "plik konfiguracji")
		_ = fs.Parse(os.Args[2:])
		err = run(*cfgPath)
	case "version":
		fmt.Println("siem-collector", version)
	default:
		err = fmt.Errorf("nieznane polecenie %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "błąd:", err)
		os.Exit(1)
	}
}

func configTemplate(serverURL string) string {
	return fmt.Sprintf(`# Kolektor syslog Heimdalla (siem-collector).
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
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var src *syslog.Source
	return hostagent.Run(hostagent.RunOptions{
		Common: &cfg.Common, Version: version, Mode: "collector", Log: log,
		MaxEventBytes: cfg.Syslog.MaxMessageKB << 10,
		Sources: func(_ string, log *slog.Logger, _ *status.Tracker) ([]source.Source, error) {
			src = &syslog.Source{Cfg: syslog.Config{UDP: cfg.Syslog.UDP, TCP: cfg.Syslog.TCP, MaxMessage: cfg.Syslog.MaxMessageKB << 10,
				Allow: allow}, Log: log}
			log.Info("kolektor: nasłuch", "udp", cfg.Syslog.UDP, "tcp", cfg.Syslog.TCP, "allow", cfg.Syslog.Allow)
			return []source.Source{src}, nil
		},
		Every: func(log *slog.Logger) {
			if src != nil {
				log.Info("syslog: liczniki", "received", src.Stats.Received.Load(), "denied", src.Stats.Denied.Load(),
					"truncated", src.Stats.Truncated.Load(), "refused_tcp", src.Stats.Refused.Load())
			}
		},
	})
}
