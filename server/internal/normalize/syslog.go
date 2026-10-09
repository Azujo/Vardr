package normalize

import (
	"os"
	"sync/atomic"
	"time"

	"siem/internal/decode"
)

// Decoders to bieżący zestaw dekoderów syslog (podmieniany przy zmianie
// dekoderów w panelu; na starcie – wbudowane).
var Decoders atomic.Pointer[decode.Set]

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
	Decoders.Store(decode.NewSet(ds))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
