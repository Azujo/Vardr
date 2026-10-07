package managed

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"siem/agent/internal/config"
	"siem/internal/contract"
)

func base() *config.Config {
	soft, hard := 150, 400
	return &config.Config{
		Server:   config.ServerConfig{URL: "https://s:8443/v1/ingest", CAFile: "ca", CertFile: "c", KeyFile: "k"},
		StateDir: "x",
		StartAt:  "now",
		Batch:    config.BatchConfig{MaxEvents: 500, MaxBytes: 4 << 20, FlushInterval: 2e9, MaxEventBytes: 512 << 10},
		Limits:   config.LimitsConfig{Priority: "below_normal", MemorySoftMB: &soft, MemoryHardMB: &hard, MaxProcs: 2},
		Logging:  config.LoggingConfig{Level: "info", MaxSizeMB: 10, MaxFiles: 3},
		Channels: []config.ChannelConfig{{Name: "Application"}},
	}
}

func TestApply(t *testing.T) {
	if eff, err := Apply(base(), nil); err != nil || eff.Channels[0].Name != "Application" {
		t.Fatalf("bez konfiguracji z panelu: %+v %v", eff, err)
	}
	eps, cpu, bg := 300, 5.0, "background"
	m := &contract.AgentConfig{Profile: "dc", Limits: contract.AgentLimits{MaxEPS: &eps, CPUMaxPercent: &cpu, Priority: &bg}}
	b := base()
	eff, err := Apply(b, m)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, ch := range eff.Channels {
		names[ch.Name] = true
	}
	if !names["Security"] || names["Application"] {
		t.Fatalf("kanały z profilu dc: %v", names)
	}
	if eff.Limits.MaxEPS != 300 || eff.Limits.CPUMaxPercent != 5 || eff.Limits.Priority != "background" || *eff.Limits.MemoryHardMB != 400 {
		t.Fatalf("limity: %+v", eff.Limits)
	}
	if b.Channels[0].Name != "Application" || b.Limits.MaxEPS != 0 {
		t.Fatal("Apply nie może zmieniać konfiguracji bazowej")
	}
}

func TestPollerFetchSaveLoad(t *testing.T) {
	cfg := contract.AgentConfig{GroupID: 2, Group: "IIS", Profile: "server"}
	cfg.Version = cfg.ComputeVersion()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"`+cfg.Version+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		json.NewEncoder(w).Encode(cfg)
	}))
	defer srv.Close()
	dir := t.TempDir()
	p := &Poller{Client: srv.Client(), PanelURL: srv.URL, StateDir: dir, Log: slog.New(slog.DiscardHandler)}

	got, err := p.Fetch(t.Context())
	if err != nil || got == nil || got.Group != "IIS" {
		t.Fatalf("pierwsze pobranie: %+v %v", got, err)
	}
	if again, err := p.Fetch(t.Context()); err != nil || again != nil {
		t.Fatalf("bez zmian powinno być nil: %+v %v", again, err)
	}
	loaded, err := Load(dir)
	if err != nil || loaded == nil || loaded.Version != cfg.Version {
		t.Fatalf("zapisana konfiguracja: %+v %v", loaded, err)
	}
	if none, err := Load(t.TempDir()); err != nil || none != nil {
		t.Fatalf("brak pliku: %+v %v", none, err)
	}
	if hits != 2 {
		t.Fatalf("żądania: %d", hits)
	}
}
