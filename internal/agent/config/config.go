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
)

// Config to konfiguracja agenta. Docelowo będzie pobierana z serwera
// (roadmapa, sekcja 7); w etapie 1 jest plikiem lokalnym.
type Config struct {
	Server   ServerConfig    `yaml:"server"`
	StateDir string          `yaml:"state_dir"`
	StartAt  string          `yaml:"start_at"`
	Batch    BatchConfig     `yaml:"batch"`
	Channels []ChannelConfig `yaml:"channels"`
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
