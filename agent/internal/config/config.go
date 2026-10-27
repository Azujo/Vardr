// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config wczytuje i waliduje konfigurację agenta.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"siem/agent/internal/limits"
	"siem/agent/internal/logging"
	"siem/internal/lang"
)

// Config to konfiguracja agenta. Docelowo będzie pobierana z serwera
// (roadmapa, sekcja 7); w etapie 1 jest plikiem lokalnym.
type Config struct {
	Server   ServerConfig    `yaml:"server"`
	StateDir string          `yaml:"state_dir"`
	StartAt  string          `yaml:"start_at"`
	Batch    BatchConfig     `yaml:"batch"`
	Limits   LimitsConfig    `yaml:"limits"`
	Buffer   BufferConfig    `yaml:"buffer"`
	Logging  LoggingConfig   `yaml:"logging"`
	Channels []ChannelConfig `yaml:"channels"`
	IIS      IISConfig       `yaml:"iis"`
}

// IISConfig: logi IIS w formacie W3C (katalog LogFiles z podkatalogami
// witryn). Włączane tu albo opcją grupy w panelu.
type IISConfig struct {
	Enabled bool   `yaml:"enabled"`
	LogDir  string `yaml:"log_dir"` // domyślnie C:\inetpub\logs\LogFiles
}

// LoggingConfig określa log agenta (plik w state_dir w trybie usługi).
type LoggingConfig struct {
	Level     string `yaml:"level"`       // debug | info | warn | error
	MaxSizeMB int    `yaml:"max_size_mb"` // rozmiar pliku przed rotacją
	MaxFiles  int    `yaml:"max_files"`   // liczba archiwalnych plików
}

// LimitsConfig to „kaganiec” agenta. Docelowo ustawiany z panelu per grupa.
type LimitsConfig struct {
	Priority      string  `yaml:"priority"`        // normal | below_normal | background
	CPUMaxPercent float64 `yaml:"cpu_max_percent"` // % całego komputera, 0 = brak
	MemorySoftMB  *int    `yaml:"memory_soft_mb"`  // brak = 150, 0 = wyłączony
	MemoryHardMB  *int    `yaml:"memory_hard_mb"`  // brak = 400, 0 = wyłączony
	MaxEPS        int     `yaml:"max_eps"`         // zdarzeń na sekundę, 0 = brak
	MaxSendKBps   int     `yaml:"max_send_kbps"`   // KiB/s po kompresji, 0 = brak
	MaxProcs      int     `yaml:"max_procs"`       // wątki wykonujące kod Go (GOMAXPROCS), domyślnie 2
}

// Resource zwraca ustawienia dla pakietu limits.
func (l LimitsConfig) Resource() limits.Limits {
	return limits.Limits{
		Priority:      l.Priority,
		CPUMaxPercent: l.CPUMaxPercent,
		MemorySoftMB:  *l.MemorySoftMB,
		MemoryHardMB:  *l.MemoryHardMB,
	}
}

// BufferConfig to dyskowy bufor paczek na czas braku łączności z serwerem
// (katalog <state_dir>\buffer). Panel może nadpisać max_mb i on_full w grupie.
type BufferConfig struct {
	MaxMB     *int   `yaml:"max_mb"`      // brak = 1024, 0 = bufor wyłączony
	OnFull    string `yaml:"on_full"`     // pause (domyślnie) | drop_oldest
	MinFreeMB int    `yaml:"min_free_mb"` // rezerwa wolnego miejsca na dysku (domyślnie 1024)
}

// MaxBytes zwraca limit bufora w bajtach (brak ustawienia = 1024 MB).
func (b BufferConfig) MaxBytes() int64 {
	if b.MaxMB == nil {
		return 1024 << 20
	}
	return int64(*b.MaxMB) << 20
}

// MBValue zwraca limit w MB (do logów).
func (b BufferConfig) MBValue() int { return int(b.MaxBytes() >> 20) }

// ServerConfig opisuje połączenie mTLS z serwerem.
type ServerConfig struct {
	URL      string        `yaml:"url"`
	CAFile   string        `yaml:"ca_file"`
	CertFile string        `yaml:"cert_file"`
	KeyFile  string        `yaml:"key_file"`
	Timeout  time.Duration `yaml:"timeout"`
	// PanelURL: adres panelu do odnawiania certyfikatu (domyślnie
	// https://<host serwera>:8444).
	PanelURL string `yaml:"panel_url"`
}

// BatchConfig określa paczkowanie (załącznik A).
type BatchConfig struct {
	MaxEvents     int           `yaml:"max_events"`
	MaxBytes      int           `yaml:"max_bytes"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	// FlushMaxWait / FlushMinEvents: paczka mniejsza niż flush_min_events
	// (domyślnie 50) czeka do flush_max_wait (domyślnie 10s) – mniej małych
	// paczek z rzadko piszących stacji. flush_max_wait = flush_interval
	// wyłącza czekanie.
	FlushMaxWait   time.Duration `yaml:"flush_max_wait"`
	FlushMinEvents int           `yaml:"flush_min_events"`
	// MaxEventBytes: dłuższe zdarzenia są przycinane i oznaczane jako truncated.
	MaxEventBytes int `yaml:"max_event_bytes"`
}

// ChannelConfig to jeden kanał Event Log i lista zbieranych Event ID
// (załącznik B). Pusta lista oznacza wszystkie zdarzenia kanału.
type ChannelConfig struct {
	Name     string   `yaml:"name"`
	EventIDs []uint32 `yaml:"event_ids"`
}

const (
	StartAtNow    = "now"
	StartAtOldest = "oldest"
)

// Load wczytuje plik YAML, uzupełnia wartości domyślne i waliduje.
// Ścieżki względne są rozwiązywane względem katalogu pliku konfiguracji.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.applyDefaults(filepath.Dir(abs))
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) applyDefaults(baseDir string) {
	if c.StateDir == "" {
		c.StateDir = filepath.Join(os.Getenv("ProgramData"), "SiemAgent")
	}
	if c.StartAt == "" {
		c.StartAt = StartAtNow
	}
	if c.Server.Timeout == 0 {
		c.Server.Timeout = 30 * time.Second
	}
	if c.Batch.MaxEvents == 0 {
		c.Batch.MaxEvents = 500
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
	if c.Batch.MaxEventBytes == 0 {
		c.Batch.MaxEventBytes = 512 << 10
	}
	if c.Limits.MaxProcs == 0 {
		c.Limits.MaxProcs = 2
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.MaxSizeMB == 0 {
		c.Logging.MaxSizeMB = 10
	}
	if c.Logging.MaxFiles == 0 {
		c.Logging.MaxFiles = 3
	}
	if c.Buffer.MaxMB == nil {
		v := 1024
		c.Buffer.MaxMB = &v
	}
	if c.Buffer.OnFull == "" {
		c.Buffer.OnFull = "pause"
	}
	if c.Buffer.MinFreeMB == 0 {
		c.Buffer.MinFreeMB = 1024
	}
	if c.Limits.Priority == "" {
		c.Limits.Priority = limits.PriorityBelowNormal
	}
	if c.Limits.MemorySoftMB == nil {
		v := 150
		c.Limits.MemorySoftMB = &v
	}
	if c.Limits.MemoryHardMB == nil {
		v := 400
		c.Limits.MemoryHardMB = &v
	}
	for _, p := range []*string{&c.StateDir, &c.Server.CAFile, &c.Server.CertFile, &c.Server.KeyFile} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(baseDir, *p)
		}
	}
}

// Validate sprawdza spójność konfiguracji.
func (c *Config) Validate() error {
	var errs []error
	if c.Server.URL == "" {
		errs = append(errs, errors.New("server.url jest wymagane"))
	}
	if c.Server.CAFile == "" || c.Server.CertFile == "" || c.Server.KeyFile == "" {
		errs = append(errs, lang.Errorf("server.ca_file, server.cert_file i server.key_file są wymagane (mTLS)", "server.ca_file, server.cert_file and server.key_file are required (mTLS)"))
	}
	if c.StartAt != StartAtNow && c.StartAt != StartAtOldest {
		errs = append(errs, lang.Errorf("start_at: dozwolone %q lub %q", "start_at: allowed %q or %q", StartAtNow, StartAtOldest))
	}
	if c.Batch.MaxEvents < 1 || c.Batch.MaxEvents > 5000 {
		errs = append(errs, lang.Errorf("batch.max_events musi być w zakresie 1–5000", "batch.max_events must be in the range 1–5000"))
	}
	if c.Batch.MaxBytes < 64<<10 {
		errs = append(errs, lang.Errorf("batch.max_bytes musi wynosić co najmniej 64 KiB", "batch.max_bytes must be at least 64 KiB"))
	}
	if c.Limits.MemorySoftMB != nil && c.Limits.MemoryHardMB != nil {
		if err := c.Limits.Resource().Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Batch.MaxEventBytes < 4<<10 || c.Batch.MaxEventBytes > c.Batch.MaxBytes {
		errs = append(errs, lang.Errorf("batch.max_event_bytes musi wynosić od 4 KiB do batch.max_bytes", "batch.max_event_bytes must be between 4 KiB and batch.max_bytes"))
	}
	if c.Limits.MaxProcs < 1 || c.Limits.MaxProcs > 64 {
		errs = append(errs, lang.Errorf("limits.max_procs musi być w zakresie 1–64", "limits.max_procs must be in the range 1–64"))
	}
	if _, err := logging.Level(c.Logging.Level); err != nil {
		errs = append(errs, fmt.Errorf("logging.level: %w", err))
	}
	if c.Logging.MaxSizeMB < 1 || c.Logging.MaxFiles < 1 || c.Logging.MaxFiles > 20 {
		errs = append(errs, lang.Errorf("logging.max_size_mb ≥ 1, logging.max_files w zakresie 1–20", "logging.max_size_mb ≥ 1, logging.max_files in the range 1–20"))
	}
	if c.Limits.MaxEPS < 0 || c.Limits.MaxSendKBps < 0 {
		errs = append(errs, lang.Errorf("limits.max_eps i limits.max_send_kbps nie mogą być ujemne", "limits.max_eps and limits.max_send_kbps cannot be negative"))
	}
	if c.Buffer.MaxMB != nil && (*c.Buffer.MaxMB < 0 || *c.Buffer.MaxMB > 102400) {
		errs = append(errs, lang.Errorf("buffer.max_mb: 0 (wyłączony) – 102400", "buffer.max_mb: 0 (disabled) – 102400"))
	}
	if c.Buffer.OnFull != "" && c.Buffer.OnFull != "pause" && c.Buffer.OnFull != "drop_oldest" {
		errs = append(errs, lang.Errorf("buffer.on_full: pause albo drop_oldest", "buffer.on_full: pause or drop_oldest"))
	}
	if c.Buffer.MinFreeMB < 0 {
		errs = append(errs, lang.Errorf("buffer.min_free_mb nie może być ujemne", "buffer.min_free_mb cannot be negative"))
	}
	if len(c.Channels) == 0 {
		errs = append(errs, lang.Errorf("brak skonfigurowanych kanałów", "no channels configured"))
	}
	seen := map[string]bool{}
	for i, ch := range c.Channels {
		if ch.Name == "" {
			errs = append(errs, lang.Errorf("channels[%d]: brak nazwy", "channels[%d]: missing name", i))
		}
		if seen[ch.Name] {
			errs = append(errs, lang.Errorf("channels[%d]: kanał %q zdefiniowany wielokrotnie", "channels[%d]: channel %q defined more than once", i, ch.Name))
		}
		seen[ch.Name] = true
	}
	return lang.Join(errs...)
}
