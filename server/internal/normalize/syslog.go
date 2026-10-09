package normalize

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/decode"
	"siem/internal/decodekv"
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
				log.Error("dekoder z panelu pominięty", "err", err)
			}
			log.Info("dekodery syslog wczytane", "decoders", n, "changed_in_panel", len(custom))
		})
	})
}
