// SPDX-License-Identifier: AGPL-3.0-or-later

package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Level zamienia nazwę poziomu z konfiguracji na slog.Level.
func Level(name string) (slog.Level, error) {
	switch strings.ToLower(name) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (debug, info, warn, error)", name)
}

// Tee rozsyła wpisy do kilku handlerów.
type Tee []slog.Handler

func (t Tee) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range t {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (t Tee) Handle(ctx context.Context, r slog.Record) error {
	var first error
	for _, h := range t {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func (t Tee) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(Tee, len(t))
	for i, h := range t {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (t Tee) WithGroup(name string) slog.Handler {
	out := make(Tee, len(t))
	for i, h := range t {
		out[i] = h.WithGroup(name)
	}
	return out
}

// Sink to miejsce docelowe wpisów systemowych (Windows Event Log).
type Sink interface {
	Info(eid uint32, msg string) error
	Warning(eid uint32, msg string) error
	Error(eid uint32, msg string) error
}

// Identyfikatory zdarzeń agenta w dzienniku Application.
const (
	EventIDInfo    = 1000
	EventIDWarning = 2000
	EventIDError   = 3000
)

// SinkHandler przekazuje ostrzeżenia i błędy do Sink, tłumiąc powtórzenia
// tego samego komunikatu w oknie czasowym – żeby np. długa przerwa w
// łączności nie zalała dziennika (który agent sam też czyta).
type SinkHandler struct {
	sink   Sink
	window time.Duration
	attrs  []slog.Attr
	state  *sinkState
}

type sinkState struct {
	mu   sync.Mutex
	last map[string]time.Time
	now  func() time.Time
}

// NewSinkHandler tworzy handler. Wpisy INFO z atrybutem eventlog=true
// (np. start i zatrzymanie) też trafiają do dziennika.
func NewSinkHandler(sink Sink, window time.Duration) *SinkHandler {
	return &SinkHandler{sink: sink, window: window,
		state: &sinkState{last: map[string]time.Time{}, now: time.Now}}
}

func (h *SinkHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h *SinkHandler) Handle(_ context.Context, r slog.Record) error {
	forced := false
	var b strings.Builder
	b.WriteString(r.Message)
	write := func(a slog.Attr) bool {
		if a.Key == "eventlog" {
			forced = a.Value.Bool()
			return true
		}
		fmt.Fprintf(&b, "\r\n%s: %v", a.Key, a.Value)
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(write)

	if r.Level < slog.LevelWarn && !forced {
		return nil
	}

	// Klucz tłumienia: poziom + komunikat (bez zmiennych atrybutów).
	key := r.Level.String() + "|" + r.Message
	s := h.state
	s.mu.Lock()
	now := s.now()
	if t, ok := s.last[key]; ok && now.Sub(t) < h.window {
		s.mu.Unlock()
		return nil
	}
	s.last[key] = now
	s.mu.Unlock()

	msg := b.String()
	switch {
	case r.Level >= slog.LevelError:
		return h.sink.Error(EventIDError, msg)
	case r.Level >= slog.LevelWarn:
		return h.sink.Warning(EventIDWarning, msg)
	default:
		return h.sink.Info(EventIDInfo, msg)
	}
}

func (h *SinkHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &c
}

func (h *SinkHandler) WithGroup(string) slog.Handler { return h }
