// SPDX-License-Identifier: AGPL-3.0-or-later

package normalize

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/decode"
	"siem/internal/decodekv"
	"siem/internal/identity"
	"siem/internal/svc"
)

// Decoders to bieżący zestaw dekoderów syslog (podmieniany przy zmianie
// dekoderów w panelu; na starcie – wbudowane).
var Decoders atomic.Pointer[decode.Set]

var builtin []*decode.Decoder

// SyslogLocation: strefa czasowa dla czasu z nagłówka syslog bez strefy
// (RFC 3164) – SIEM_SYSLOG_TZ, domyślnie Europe/Warsaw.
var SyslogLocation = time.UTC

func init() {
	if loc, err := time.LoadLocation(envOr("SIEM_SYSLOG_TZ", "Europe/Warsaw")); err == nil {
		SyslogLocation = loc
	}
	ds, err := decode.Builtin(SyslogLocation)
	if err != nil {
		panic("wbudowane dekodery: " + err.Error()) // błąd w repozytorium – wykrywa test
	}
	builtin = ds
	Decoders.Store(decode.NewSet(ds))
}

// SetCustom podmienia zestaw dekoderów: wbudowane ze zmianami z panelu.
// Zwraca liczbę dekoderów w zestawie i błędy definicji (pominiętych).
func SetCustom(custom map[string]decode.Custom) (int, []error) {
	set, errs := decode.Merge(builtin, custom, SyslogLocation)
	Decoders.Store(set)
	return len(set.List()), errs
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Gotowość konfiguracji z panelu (dekodery, tożsamości) – normalizator
// czeka na nią przy starcie, żeby pierwsze zdarzenia po restarcie nie
// dostały ustawień domyślnych.
var (
	decodersOnce, identityOnce   sync.Once
	decodersReady, identityReady = make(chan struct{}), make(chan struct{})
)

// WaitConfig czeka na wczytanie dekoderów i tożsamości z NATS (najwyżej
// timeout – potem praca na ustawieniach domyślnych z ostrzeżeniem).
func WaitConfig(ctx context.Context, timeout time.Duration, log *slog.Logger) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	for _, c := range []struct {
		ch   chan struct{}
		what string
	}{{decodersReady, "dekodery"}, {identityReady, "tożsamości"}} {
		select {
		case <-c.ch:
		case <-ctx.Done():
			return
		case <-t.C:
			log.Warn("configuration from the panel not loaded – starting with defaults", "what", c.what, "timeout", timeout)
			return
		}
	}
}

// WatchDecoders obserwuje dekodery z panelu (NATS KV) i podmienia zestaw do
// zakończenia ctx – normalizator i archiwizator (czytelna część eksportu
// dekodowana tak jak zdarzenia w bazie). Do czasu wczytania: wbudowane.
func WatchDecoders(ctx context.Context, js jetstream.JetStream, log *slog.Logger) {
	_ = svc.Retry(ctx, log, "dekodery z panelu", func() error {
		kv, err := decodekv.Ensure(ctx, js)
		if err != nil {
			return err
		}
		return decodekv.Watch(ctx, kv, log, func(custom map[string]decode.Custom) {
			n, errs := SetCustom(custom)
			for _, err := range errs {
				log.Error("decoder from the panel skipped", "err", err)
			}
			log.Info("syslog decoders loaded", "decoders", n, "changed_in_panel", len(custom))
			decodersOnce.Do(func() { close(decodersReady) })
		})
	})
}

// WatchIdentity obserwuje konfigurację tożsamości z panelu (NATS KV) do
// zakończenia ctx. Do czasu wczytania: każda domena „swoja”, bez aliasów.
func WatchIdentity(ctx context.Context, js jetstream.JetStream, log *slog.Logger) {
	_ = svc.Retry(ctx, log, "identities from the panel", func() error {
		kv, err := identity.Ensure(ctx, js)
		if err != nil {
			return err
		}
		return identity.Watch(ctx, kv, log, func() { identityOnce.Do(func() { close(identityReady) }) })
	})
}
