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
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"siem/agent/internal/core"
	"siem/agent/internal/enrollment"
	"siem/agent/internal/heartbeat"
	"siem/agent/internal/setup"
	"siem/agent/internal/shipper"
	"siem/agent/internal/source"
	"siem/agent/internal/spool"
	"siem/agent/internal/state"
	"siem/agent/internal/status"
	"siem/agent/internal/syslog"
)

var version = "dev"

// Config to collector.yaml.
type Config struct {
	Server struct {
		URL      string        `yaml:"url"`
		PanelURL string        `yaml:"panel_url"`
		CAFile   string        `yaml:"ca_file"`
		CertFile string        `yaml:"cert_file"`
		KeyFile  string        `yaml:"key_file"`
		Timeout  time.Duration `yaml:"timeout"`
	} `yaml:"server"`
	StateDir string `yaml:"state_dir"`
	Syslog   struct {
		UDP          string   `yaml:"udp"`
		TCP          string   `yaml:"tcp"`
		MaxMessageKB int      `yaml:"max_message_kb"`
		Allow        []string `yaml:"allow"`
	} `yaml:"syslog"`
	Batch struct {
		MaxEvents     int           `yaml:"max_events"`
		MaxBytes      int           `yaml:"max_bytes"`
		FlushInterval time.Duration `yaml:"flush_interval"`
	} `yaml:"batch"`
	Buffer struct {
		MaxMB     int    `yaml:"max_mb"`
		OnFull    string `yaml:"on_full"` // pause | drop_oldest
		MinFreeMB int    `yaml:"min_free_mb"`
	} `yaml:"buffer"`
	MaxEPS int `yaml:"max_eps"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	dec := yaml.NewDecoder(bytesReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	base := filepath.Dir(path)
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	c.Server.CAFile, c.Server.CertFile, c.Server.KeyFile = abs(c.Server.CAFile), abs(c.Server.CertFile), abs(c.Server.KeyFile)
	c.StateDir = abs(c.StateDir)
	switch {
	case c.Server.URL == "":
		return nil, errors.New("server.url: brak adresu serwera")
	case c.Syslog.UDP == "" && c.Syslog.TCP == "":
		return nil, errors.New("syslog: podaj udp albo tcp (np. \":514\")")
	case c.Buffer.OnFull != "" && c.Buffer.OnFull != "pause" && c.Buffer.OnFull != "drop_oldest":
		return nil, errors.New("buffer.on_full: pause albo drop_oldest")
	}
	if c.Server.Timeout == 0 {
		c.Server.Timeout = 30 * time.Second
	}
	if c.StateDir == "" {
		c.StateDir = filepath.Join(base, "state")
	}
	if c.Batch.MaxEvents == 0 {
		c.Batch.MaxEvents = 2000
	}
	if c.Batch.MaxBytes == 0 {
		c.Batch.MaxBytes = 4 << 20
	}
	if c.Batch.FlushInterval == 0 {
		c.Batch.FlushInterval = 2 * time.Second
	}
	if c.Buffer.MaxMB == 0 {
		c.Buffer.MaxMB = 2048
	}
	if c.Buffer.OnFull == "" {
		// Syslog nie da się odczytać ponownie z urządzenia – przy pełnym buforze
		// lepiej stracić najstarsze niż wstrzymać odbiór (wtedy giną najnowsze).
		c.Buffer.OnFull = "drop_oldest"
	}
	if c.Buffer.MinFreeMB == 0 {
		c.Buffer.MinFreeMB = 1024
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
		err = enroll(*server, *token, *ca, *panel, *dir)
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

// enroll rejestruje kolektor tokenem i zapisuje certyfikaty oraz collector.yaml.
func enroll(server, token, caFile, panel, dir string) error {
	if server == "" || token == "" {
		return errors.New("podaj -server i -token")
	}
	serverURL, err := setup.ServerURL(server)
	if err != nil {
		return err
	}
	if panel == "" {
		if panel, err = enrollment.PanelURL(serverURL); err != nil {
			return err
		}
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("plik CA (-ca): %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("niepoprawny plik CA")
	}
	certDir := filepath.Join(dir, "certs")
	if _, err := os.Stat(filepath.Join(certDir, "agent.key")); err == nil {
		return fmt.Errorf("%s zawiera już klucz kolektora – wskaż pusty katalog", dir)
	}
	host, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, keyPEM, err := enrollment.Register(ctx, panel, roots, token,
		enrollment.Info{Hostname: host, OS: "kolektor syslog (" + heartbeat.OSVersion() + ")", Version: version})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "ca.crt"), caPEM, 0o644); err != nil {
		return err
	}
	if err := enrollment.WritePair(filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"), []byte(res.Certificate), keyPEM); err != nil {
		return err
	}
	cfg := fmt.Sprintf(`# Kolektor syslog Heimdalla (siem-collector).
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
  # allow: ["192.168.88.0/24"]   # tylko te sieci (puste = wszyscy)
buffer:
  max_mb: 2048
  on_full: drop_oldest
`, serverURL)
	if err := os.WriteFile(filepath.Join(dir, "collector.yaml"), []byte(cfg), 0o600); err != nil {
		return err
	}
	fmt.Printf("Zarejestrowano kolektor %s (certyfikat ważny do %s).\nKonfiguracja: %s\n", res.AgentID,
		res.NotAfter.Local().Format("2006-01-02"), filepath.Join(dir, "collector.yaml"))
	return nil
}

func run(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("katalog stanu: %w", err)
	}
	var allow []netip.Prefix
	for _, a := range cfg.Syslog.Allow {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return fmt.Errorf("syslog.allow %q: %w", a, err)
		}
		allow = append(allow, p.Masked())
	}

	client, certs, err := shipper.NewReloadableTLSClient(cfg.Server.CAFile, cfg.Server.CertFile, cfg.Server.KeyFile, cfg.Server.Timeout)
	if err != nil {
		return err
	}
	agentID := certs.AgentID()
	log = log.With("agent_id", agentID)
	tracker := status.NewTracker(version, agentID, cfg.Server.URL, map[string]any{"mode": "collector"})
	store := state.NewStore(cfg.StateDir)
	sender := shipper.NewHTTPSender(client, cfg.Server.URL, filepath.Join(cfg.StateDir, "quarantine"), log)
	sender.AttachStatus(tracker)

	bg, stopBg := context.WithCancel(ctx)
	defer stopBg()
	go tracker.Run(bg, cfg.StateDir, 5*time.Second)

	buf, err := spool.Open(filepath.Join(cfg.StateDir, "buffer"), sender, log)
	if err != nil {
		return fmt.Errorf("bufor dyskowy: %w", err)
	}
	buf.FreeSpace = spool.DiskFree
	buf.Configure(int64(cfg.Buffer.MaxMB)<<20, cfg.Buffer.OnFull, int64(cfg.Buffer.MinFreeMB)<<20)
	go buf.Run(bg)
	tracker.SetProbe("buffer", func(s *status.Status) {
		b := buf.Stats()
		s.Buffer = &status.BufferStatus{Batches: b.Batches, Bytes: b.Bytes, MaxBytes: b.MaxBytes, OnFull: b.OnFull,
			OldestAt: b.OldestAt, Spooled: b.Spooled, Dropped: b.Dropped, Full: b.Full, Disabled: b.Disabled,
			LastError: b.LastError, LastErrorTime: b.LastErrorTime}
	})

	if hbURL, err := heartbeat.URLFromIngest(cfg.Server.URL); err == nil {
		hb := &heartbeat.Sender{Client: client, URL: hbURL, AgentID: agentID, Version: version, Started: time.Now(),
			Status: func() any { return tracker.Snapshot() }, Clock: tracker.SetClock, Log: log}
		go hb.Run(bg)
	}
	panelURL := cfg.Server.PanelURL
	if panelURL == "" {
		panelURL, _ = enrollment.PanelURL(cfg.Server.URL)
	}
	if panelURL != "" {
		renewer := &enrollment.Renewer{Client: client, PanelURL: panelURL, CertFile: cfg.Server.CertFile, KeyFile: cfg.Server.KeyFile,
			Holder: certs, Log: log, Warn: tracker.Warn}
		go renewer.Run(bg)
	}

	src := &syslog.Source{Cfg: syslog.Config{UDP: cfg.Syslog.UDP, TCP: cfg.Syslog.TCP, MaxMessage: cfg.Syslog.MaxMessageKB << 10,
		Allow: allow}, Log: log}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-bg.Done():
				return
			case <-t.C:
				log.Info("syslog: liczniki", "received", src.Stats.Received.Load(), "denied", src.Stats.Denied.Load(),
					"truncated", src.Stats.Truncated.Load(), "refused_tcp", src.Stats.Refused.Load())
			}
		}
	}()

	agent := core.New(core.Options{
		AgentID:       agentID,
		MaxEvents:     cfg.Batch.MaxEvents,
		MaxBytes:      cfg.Batch.MaxBytes,
		MaxEventBytes: cfg.Syslog.MaxMessageKB << 10,
		FlushInterval: cfg.Batch.FlushInterval,
		MaxEPS:        cfg.MaxEPS,
		Status:        tracker,
		RetryDelay:    func(error) time.Duration { return 5 * time.Second },
	}, []source.Source{src}, buf, store, log)
	log.Info("kolektor uruchomiony", "version", version, "udp", cfg.Syslog.UDP, "tcp", cfg.Syslog.TCP, "allow", cfg.Syslog.Allow)
	err = agent.Run(ctx)
	s := sender.Stats
	log.Info("kolektor zatrzymany", "batches_accepted", s.BatchesAccepted.Load(), "events_accepted", s.EventsAccepted.Load())
	return err
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
