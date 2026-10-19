package backup

import (
	"slices"
	"testing"
	"time"

	"siem/internal/backupcfg"
)

func TestExpired(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	f := func(day int) remoteFile {
		ts := time.Date(2026, 10, day, 2, 15, 0, 0, time.UTC)
		return remoteFile{Name: "heimdall-" + ts.Format("20060102-1504") + "-k1234abcd.tar.gpg", ModTime: now} // czas wysyłki – bez znaczenia
	}
	files := []remoteFile{f(19), f(18), f(10), f(5), f(1)}
	name := func(day int) string { return f(day).Name }

	// Tylko dni: starsze niż 7 dni od 19.10 12:00 – 10.10, 5.10, 1.10.
	if got := expired(slices.Clone(files), backupcfg.Retention{KeepDays: 7}, now); !slices.Equal(got, []string{name(10), name(5), name(1)}) {
		t.Fatalf("7 dni: %v", got)
	}
	// Dni i liczba: najwyżej 2 kopie.
	if got := expired(slices.Clone(files), backupcfg.Retention{KeepDays: 30, KeepCount: 2}, now); !slices.Equal(got, []string{name(10), name(5), name(1)}) {
		t.Fatalf("2 kopie: %v", got)
	}
	// Najnowsza zostaje zawsze, nawet stara.
	old := []remoteFile{f(1)}
	if got := expired(old, backupcfg.Retention{KeepDays: 1}, now); len(got) != 0 {
		t.Fatalf("najnowsza usunięta: %v", got)
	}
	// Nazwa bez czasu – według czasu modyfikacji.
	other := []remoteFile{{Name: "x.tar.gpg", ModTime: now.Add(-40 * 24 * time.Hour)}, f(19)}
	if got := expired(other, backupcfg.Retention{KeepDays: 30}, now); !slices.Equal(got, []string{"x.tar.gpg"}) {
		t.Fatalf("bez czasu w nazwie: %v", got)
	}
	if passIDOf([]byte("abc")) != "kba7816bf" {
		t.Fatalf("identyfikator hasła: %s (ma się zgadzać z sha256sum w backup.sh)", passIDOf([]byte("abc")))
	}
}
