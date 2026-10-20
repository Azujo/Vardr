// Package hostagent to wspólny szkielet agentów serwerowych Vardra –
// kolektora syslog (siem-collector) i konektora API (siem-connector):
// konfiguracja, rejestracja tokenem i praca jak agent Windows (mTLS,
// paczki, bufor dyskowy, heartbeat w panelu, odnawianie certyfikatu).
package hostagent

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
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
)

// Common to ustawienia wspólne (w pliku konfiguracji na najwyższym poziomie).
type Common struct {
	Server struct {
		URL      string        `yaml:"url"`
		PanelURL string        `yaml:"panel_url"`
		CAFile   string        `yaml:"ca_file"`
		CertFile string        `yaml:"cert_file"`
		KeyFile  string        `yaml:"key_file"`
		Timeout  time.Duration `yaml:"timeout"`
	} `yaml:"server"`
	StateDir string `yaml:"state_dir"`
	Batch    struct {
		MaxEvents     int           `yaml:"max_events"`
		MaxBytes      int           `yaml:"max_bytes"`
		FlushInterval time.Duration `yaml:"flush_interval"`
		// Czekanie małej paczki (jak w agencie Windows): domyślnie 10s / 50 zdarzeń.
		FlushMaxWait   time.Duration `yaml:"flush_max_wait"`
		FlushMinEvents int           `yaml:"flush_min_events"`
	} `yaml:"batch"`
	Buffer struct {
		MaxMB     int    `yaml:"max_mb"`
		OnFull    string `yaml:"on_full"` // pause | drop_oldest
		MinFreeMB int    `yaml:"min_free_mb"`
	} `yaml:"buffer"`
	MaxEPS int `yaml:"max_eps"`
}

// Load wczytuje plik konfiguracji do cfg (nieznane klucze to błąd), a potem
// uzupełnia i sprawdza część wspólną (ścieżki względem katalogu pliku).
// base zwraca katalog pliku – dla ścieżek własnych sekcji.
func Load(path string, cfg any, c *Common) (base string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	base = filepath.Dir(path)
	c.Server.CAFile, c.Server.CertFile, c.Server.KeyFile = Abs(base, c.Server.CAFile), Abs(base, c.Server.CertFile), Abs(base, c.Server.KeyFile)
	c.StateDir = Abs(base, c.StateDir)
	switch {
	case c.Server.URL == "":
		return "", errors.New("server.url: brak adresu serwera")
	case c.Buffer.OnFull != "" && c.Buffer.OnFull != "pause" && c.Buffer.OnFull != "drop_oldest":
		return "", errors.New("buffer.on_full: pause albo drop_oldest")
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
	if c.Batch.FlushMaxWait == 0 {
		c.Batch.FlushMaxWait = 10 * time.Second
	}
	if c.Batch.FlushMinEvents == 0 {
		c.Batch.FlushMinEvents = 50
	}
	if c.Buffer.MaxMB == 0 {
		c.Buffer.MaxMB = 2048
	}
	if c.Buffer.OnFull == "" {
		// Źródeł tych agentów zwykle nie da się odczytać ponownie (syslog) –
		// przy pełnym buforze lepiej stracić najstarsze niż wstrzymać odbiór.
		c.Buffer.OnFull = "drop_oldest"
	}
	if c.Buffer.MinFreeMB == 0 {
		c.Buffer.MinFreeMB = 1024
	}
	return base, nil
}

// Abs: ścieżka względem katalogu base (pusta i bezwzględna bez zmian).
func Abs(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// EnrollOptions to parametry rejestracji.
type EnrollOptions struct {
	Server, Token, CAFile, Panel, Dir string
	OS                                string // opis w panelu, np. „kolektor syslog”
	Version                           string
	ConfigName                        string                        // np. collector.yaml
	Config                            func(serverURL string) string // treść pliku konfiguracji
}

// Enroll rejestruje agenta tokenem i zapisuje certyfikaty oraz plik konfiguracji.
func Enroll(o EnrollOptions) error {
	if o.Server == "" || o.Token == "" {
		return errors.New("podaj -server i -token")
	}
	serverURL, err := setup.ServerURL(o.Server)
	if err != nil {
		return err
	}
	panel := o.Panel
	if panel == "" {
		if panel, err = enrollment.PanelURL(serverURL); err != nil {
			return err
		}
	}
	caPEM, err := os.ReadFile(o.CAFile)
	if err != nil {
		return fmt.Errorf("plik CA (-ca): %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("niepoprawny plik CA")
	}
	certDir := filepath.Join(o.Dir, "certs")
	if _, err := os.Stat(filepath.Join(certDir, "agent.key")); err == nil {
		return fmt.Errorf("%s zawiera już klucz – wskaż pusty katalog", o.Dir)
	}
	host, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, keyPEM, err := enrollment.Register(ctx, panel, roots, o.Token,
		enrollment.Info{Hostname: host, OS: o.OS + " (" + heartbeat.OSVersion() + ")", Version: o.Version})
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
	cfgPath := filepath.Join(o.Dir, o.ConfigName)
	if err := os.WriteFile(cfgPath, []byte(o.Config(serverURL)), 0o600); err != nil {
		return err
	}
	fmt.Printf("Zarejestrowano %s (certyfikat ważny do %s).\nKonfiguracja: %s\n", res.AgentID,
		res.NotAfter.Local().Format("2006-01-02"), cfgPath)
	return nil
}

// RunOptions to parametry pracy.
type RunOptions struct {
	Common  *Common
	Version string
	Mode    string // w statusie agenta: collector | connector
	// Sources budują źródła (z identyfikatorem agenta z certyfikatu; st –
	// stan agenta w panelu, np. błędy źródła).
	Sources       func(agentID string, log *slog.Logger, st *status.Tracker) ([]source.Source, error)
	MaxEventBytes int
	// Every (opcjonalne) – wywoływane co minutę (np. liczniki w dzienniku).
	Every func(log *slog.Logger)
	Log   *slog.Logger
}

// Run pracuje do sygnału zakończenia.
func Run(o RunOptions) error {
	c := o.Common
	log := o.Log
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return fmt.Errorf("katalog stanu: %w", err)
	}
	client, certs, err := shipper.NewReloadableTLSClient(c.Server.CAFile, c.Server.CertFile, c.Server.KeyFile, c.Server.Timeout)
	if err != nil {
		return err
	}
	agentID := certs.AgentID()
	log = log.With("agent_id", agentID)
	tracker := status.NewTracker(o.Version, agentID, c.Server.URL, map[string]any{"mode": o.Mode})
	store := state.NewStore(c.StateDir)
	sender := shipper.NewHTTPSender(client, c.Server.URL, filepath.Join(c.StateDir, "quarantine"), log)
	sender.AttachStatus(tracker)

	bg, stopBg := context.WithCancel(ctx)
	defer stopBg()
	go tracker.Run(bg, c.StateDir, 5*time.Second)

	buf, err := spool.Open(filepath.Join(c.StateDir, "buffer"), sender, log)
	if err != nil {
		return fmt.Errorf("bufor dyskowy: %w", err)
	}
	buf.FreeSpace = spool.DiskFree
	buf.Configure(int64(c.Buffer.MaxMB)<<20, c.Buffer.OnFull, int64(c.Buffer.MinFreeMB)<<20)
	go buf.Run(bg)
	tracker.SetProbe("buffer", func(s *status.Status) {
		b := buf.Stats()
		s.Buffer = &status.BufferStatus{Batches: b.Batches, Bytes: b.Bytes, MaxBytes: b.MaxBytes, OnFull: b.OnFull,
			OldestAt: b.OldestAt, Spooled: b.Spooled, Dropped: b.Dropped, Full: b.Full, Disabled: b.Disabled,
			LastError: b.LastError, LastErrorTime: b.LastErrorTime}
	})

	if hbURL, err := heartbeat.URLFromIngest(c.Server.URL); err == nil {
		hb := &heartbeat.Sender{Client: client, URL: hbURL, AgentID: agentID, Version: o.Version, Started: time.Now(),
			Status: func() any { return tracker.Snapshot() }, Clock: tracker.SetClock, Log: log}
		go hb.Run(bg)
	}
	panelURL := c.Server.PanelURL
	if panelURL == "" {
		panelURL, _ = enrollment.PanelURL(c.Server.URL)
	}
	if panelURL != "" {
		renewer := &enrollment.Renewer{Client: client, PanelURL: panelURL, CertFile: c.Server.CertFile, KeyFile: c.Server.KeyFile,
			Holder: certs, Log: log, Warn: tracker.Warn}
		go renewer.Run(bg)
	}
	sources, err := o.Sources(agentID, log, tracker)
	if err != nil {
		return err
	}
	if o.Every != nil {
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-bg.Done():
					return
				case <-t.C:
					o.Every(log)
				}
			}
		}()
	}
	agent := core.New(core.Options{
		AgentID:       agentID,
		MaxEvents:     c.Batch.MaxEvents,
		MaxBytes:      c.Batch.MaxBytes,
		MaxEventBytes: o.MaxEventBytes,
		FlushInterval: c.Batch.FlushInterval,
		FlushMaxWait:  c.Batch.FlushMaxWait, FlushMinEvents: c.Batch.FlushMinEvents,
		MaxEPS:     c.MaxEPS,
		Status:     tracker,
		RetryDelay: func(error) time.Duration { return 5 * time.Second },
	}, sources, buf, store, log)
	log.Info("uruchomiony", "mode", o.Mode, "version", o.Version)
	err = agent.Run(ctx)
	s := sender.Stats
	log.Info("zatrzymany", "batches_accepted", s.BatchesAccepted.Load(), "events_accepted", s.EventsAccepted.Load())
	return err
}
