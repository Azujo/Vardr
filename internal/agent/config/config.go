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

	"siem/internal/agent/limits"
	"siem/internal/agent/logging"
)

// Config to konfiguracja agenta. Docelowo będzie pobierana z serwera
// (roadmapa, sekcja 7); w etapie 1 jest plikiem lokalnym.
type Config struct {
	Server   ServerConfig    `yaml:"server"`
	StateDir string          `yaml:"state_dir"`
	StartAt  string          `yaml:"start_at"`
	Batch    BatchConfig     `yaml:"batch"`
	Limits   LimitsConfig    `yaml:"limits"`
	Logging  LoggingConfig   `yaml:"logging"`
	Channels []ChannelConfig `yaml:"channels"`
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

// ServerConfig opisuje połączenie mTLS z serwerem.
type ServerConfig struct {
	URL      string        `yaml:"url"`
	CAFile   string        `yaml:"ca_file"`
	CertFile string        `yaml:"cert_file"`
	KeyFile  string        `yaml:"key_file"`
	Timeout  time.Duration `yaml:"timeout"`
}

// BatchConfig określa paczkowanie (załącznik A).
type BatchConfig struct {
	MaxEvents     int           `yaml:"max_events"`
	MaxBytes      int           `yaml:"max_bytes"`
	FlushInterval time.Duration `yaml:"flush_interval"`
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
		errs = append(errs, errors.New("server.ca_file, server.cert_file i server.key_file są wymagane (mTLS)"))
	}
	if c.StartAt != StartAtNow && c.StartAt != StartAtOldest {
		errs = append(errs, fmt.Errorf("start_at: dozwolone %q lub %q", StartAtNow, StartAtOldest))
	}
	if c.Batch.MaxEvents < 1 || c.Batch.MaxEvents > 5000 {
		errs = append(errs, errors.New("batch.max_events musi być w zakresie 1–5000"))
	}
	if c.Batch.MaxBytes < 64<<10 {
		errs = append(errs, errors.New("batch.max_bytes musi wynosić co najmniej 64 KiB"))
	}
	if c.Limits.MemorySoftMB != nil && c.Limits.MemoryHardMB != nil {
		if err := c.Limits.Resource().Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Batch.MaxEventBytes < 4<<10 || c.Batch.MaxEventBytes > c.Batch.MaxBytes {
		errs = append(errs, errors.New("batch.max_event_bytes musi wynosić od 4 KiB do batch.max_bytes"))
	}
	if c.Limits.MaxProcs < 1 || c.Limits.MaxProcs > 64 {
		errs = append(errs, errors.New("limits.max_procs musi być w zakresie 1–64"))
	}
	if _, err := logging.Level(c.Logging.Level); err != nil {
		errs = append(errs, fmt.Errorf("logging.level: %w", err))
	}
	if c.Logging.MaxSizeMB < 1 || c.Logging.MaxFiles < 1 || c.Logging.MaxFiles > 20 {
		errs = append(errs, errors.New("logging.max_size_mb ≥ 1, logging.max_files w zakresie 1–20"))
	}
	if c.Limits.MaxEPS < 0 || c.Limits.MaxSendKBps < 0 {
		errs = append(errs, errors.New("limits.max_eps i limits.max_send_kbps nie mogą być ujemne"))
	}
	if len(c.Channels) == 0 {
		errs = append(errs, errors.New("brak skonfigurowanych kanałów"))
	}
	seen := map[string]bool{}
	for i, ch := range c.Channels {
		if ch.Name == "" {
			errs = append(errs, fmt.Errorf("channels[%d]: brak nazwy", i))
		}
		if seen[ch.Name] {
			errs = append(errs, fmt.Errorf("channels[%d]: kanał %q zdefiniowany wielokrotnie", i, ch.Name))
		}
		seen[ch.Name] = true
	}
	return errors.Join(errs...)
}
