// SPDX-License-Identifier: AGPL-3.0-or-later

// Command siem-connector to agent Vardra w trybie konektora API: pobiera
// logi z usług chmurowych (etap 7: Entra ID przez Microsoft Graph –
// logowania i zmiany w katalogu) i wysyła je do serwera tak jak agent
// Windows – mTLS, paczki, bufor dyskowy, heartbeat w panelu (Huginn),
// odnawianie certyfikatu. Kursor odczytu jest w stanie konektora.
//
//	siem-connector enroll -server <adres> -token <token> -ca ca.crt -dir <katalog>
//	siem-connector run -config <katalog>/connector.yaml
//	siem-connector version
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"siem/agent/internal/graph"
	"siem/agent/internal/hostagent"
	"siem/agent/internal/source"
	"siem/agent/internal/status"
)

var version = "dev"

// Config to connector.yaml.
type Config struct {
	hostagent.Common `yaml:",inline"`
	Entra            struct {
		TenantID         string        `yaml:"tenant_id"`
		ClientID         string        `yaml:"client_id"`
		ClientSecretFile string        `yaml:"client_secret_file"` // plik z sekretem aplikacji (nie w konfiguracji)
		LoginURL         string        `yaml:"login_url"`          // domyślnie https://login.microsoftonline.com
		GraphURL         string        `yaml:"graph_url"`          // domyślnie https://graph.microsoft.com
		SignIns          *bool         `yaml:"sign_ins"`           // logowania (domyślnie tak; wymaga Entra ID P1/P2)
		Audits           *bool         `yaml:"audits"`             // zmiany w katalogu (domyślnie tak)
		Interval         time.Duration `yaml:"interval"`           // domyślnie 1m
		Overlap          time.Duration `yaml:"overlap"`            // zakładka na opóźnienie logów, domyślnie 15m
		Lookback         time.Duration `yaml:"lookback"`           // pierwszy start, domyślnie 24h
	} `yaml:"entra"`
}

func loadConfig(path string) (*Config, string, error) {
	c := &Config{}
	base, err := hostagent.Load(path, c, &c.Common)
	if err != nil {
		return nil, "", err
	}
	e := &c.Entra
	switch {
	case e.TenantID == "" || e.ClientID == "" || e.ClientSecretFile == "":
		return nil, "", errors.New("entra: podaj tenant_id, client_id i client_secret_file")
	case e.Interval != 0 && e.Interval < 30*time.Second:
		return nil, "", errors.New("entra.interval: co najmniej 30s (limity Graph)")
	}
	for _, u := range []string{e.LoginURL, e.GraphURL} {
		if u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			return nil, "", fmt.Errorf("entra: address %q without http(s)://", u)
		}
	}
	return c, base, nil
}

func enabled(b *bool) bool { return b == nil || *b }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: siem-connector enroll|run|version …")
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
		dir := fs.String("dir", ".", "connector directory (certificates, connector.yaml, state)")
		_ = fs.Parse(os.Args[2:])
		err = hostagent.Enroll(hostagent.EnrollOptions{Server: *server, Token: *token, CAFile: *ca, Panel: *panel, Dir: *dir,
			OS: "konektor API", Version: version, ConfigName: "connector.yaml", Config: configTemplate})
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		cfgPath := fs.String("config", "connector.yaml", "configuration file")
		_ = fs.Parse(os.Args[2:])
		err = run(*cfgPath)
	case "version":
		fmt.Println("siem-connector", version)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func configTemplate(serverURL string) string {
	return fmt.Sprintf(`# Konektor API Vardra (siem-connector).
server:
  url: %s
  ca_file: certs/ca.crt
  cert_file: certs/agent.crt
  key_file: certs/agent.key
state_dir: state
# Entra ID (Microsoft Graph): rejestracja aplikacji z uprawnieniami aplikacji
# AuditLog.Read.All i Directory.Read.All (zgoda administratora). Sekret
# aplikacji w osobnym pliku (prawa tylko dla konektora).
entra:
  tenant_id: "00000000-0000-0000-0000-000000000000"
  client_id: "00000000-0000-0000-0000-000000000000"
  client_secret_file: entra.secret
  # sign_ins: true      # logowania (wymaga licencji Entra ID P1/P2)
  # audits: true        # zmiany w katalogu
  # interval: 1m
  # overlap: 15m        # logi pojawiają się w Graph z opóźnieniem
  # lookback: 24h       # pierwszy start
  # login_url / graph_url – tylko dla symulatora (tools/cmd/entrasim)
buffer:
  max_mb: 2048
  on_full: drop_oldest
`, serverURL)
}

func run(cfgPath string) error {
	cfg, base, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	e := cfg.Entra
	secret, err := os.ReadFile(hostagent.Abs(base, e.ClientSecretFile))
	if err != nil {
		return fmt.Errorf("entra.client_secret_file: %w", err)
	}
	client := graph.NewClient(graph.Config{TenantID: e.TenantID, ClientID: e.ClientID, ClientSecret: strings.TrimSpace(string(secret)),
		LoginURL: e.LoginURL, GraphURL: e.GraphURL})
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return hostagent.Run(hostagent.RunOptions{
		Common: &cfg.Common, Version: version, Mode: "connector", Log: log,
		MaxEventBytes: 256 << 10,
		Sources: func(_ string, log *slog.Logger, st *status.Tracker) ([]source.Source, error) {
			var srcs []source.Source
			for _, k := range []struct {
				on   bool
				kind graph.Kind
			}{{enabled(e.SignIns), graph.SignIns}, {enabled(e.Audits), graph.Audits}} {
				if k.on {
					ch := k.kind.Channel
					srcs = append(srcs, &graph.Source{Client: client, Kind: k.kind, Interval: e.Interval, Overlap: e.Overlap,
						Lookback: e.Lookback, Log: log, State: func(state, msg string) { st.ChannelState(ch, state, msg) }})
				}
			}
			if len(srcs) == 0 {
				return nil, errors.New("entra: enable sign_ins or audits")
			}
			log.Info("konektor Entra ID", "tenant", e.TenantID, "graph", graphURL(e.GraphURL), "sources", len(srcs))
			return srcs, nil
		},
	})
}

func graphURL(u string) string {
	if u == "" {
		return "https://graph.microsoft.com"
	}
	return u
}
