// Package svc zawiera wspólne elementy programów serwera: konfigurację ze
// zmiennych środowiskowych (kontenery), log JSON i obsługę zatrzymania.
package svc

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// Logger zwraca log JSON na stdout (zbierany przez Dockera) i zapisuje
// wersję programu – po wdrożeniu widać w logu, co faktycznie działa.
func Logger(component string) *slog.Logger {
	l := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", component)
	l.Info("start", "version", Version)
	return l
}

// Context kończy się po SIGINT/SIGTERM (docker stop).
func Context() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// Env zwraca wartość zmiennej lub wartość domyślną.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// MustEnv zwraca wartość wymaganej zmiennej albo kończy program.
func MustEnv(log *slog.Logger, key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Error("brak wymaganej zmiennej środowiskowej", "name", key)
		os.Exit(2)
	}
	return v
}

// EnvDuration czyta czas trwania (np. "48h").
func EnvDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// EnvInt czyta liczbę całkowitą.
func EnvInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// Retry ponawia fn z rosnącym opóźnieniem do sukcesu lub anulowania
// (np. czekanie na start NATS / ClickHouse w docker compose).
func Retry(ctx context.Context, log *slog.Logger, what string, fn func() error) error {
	delay := time.Second
	for {
		err := fn()
		if err == nil {
			return nil
		}
		log.Warn("nieudane – ponowię", "what", what, "err", err, "retry_in", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

// EnvFloat czyta liczbę zmiennoprzecinkową.
func EnvFloat(key string, def float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return f, nil
}

// Version to wersja usług serwera i panelu (nadpisywana przy budowaniu:
// -ldflags "-X siem/internal/svc.Version=…").
var Version = "0.4.0-dev"
