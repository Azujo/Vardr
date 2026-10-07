package logwatch

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestAssess(t *testing.T) {
	// Pełny dziennik 1000 rekordów (101–1100), agent na 600: 500 niewysłanych.
	info := Info{Records: 1000, Oldest: 101, FileSize: 20 << 20, MaxSize: 20 << 20}
	a := Assess(info, 600, 10)
	if a.Unread != 500 || a.Risk != 0.5 || a.Lost != 0 || a.TimeLeft != 50*time.Second {
		t.Fatalf("%+v", a)
	}
	// Agent na 50, a najstarszy to 101: 50 rekordów nadpisanych.
	if a := Assess(info, 50, 0); a.Lost != 50 || a.Unread != 1000 || a.Risk != 1 {
		t.Fatalf("utrata: %+v", a)
	}
	// Dziennik zapełniony w 25%: pojemność 4× większa, ryzyko 4× mniejsze.
	if a := Assess(Info{Records: 1000, Oldest: 1, FileSize: 5 << 20, MaxSize: 20 << 20}, 500, 0); a.Risk != 0.125 {
		t.Fatalf("niepełny dziennik: %+v", a)
	}
	if a := Assess(Info{}, 0, 0); a != (Assessment{}) {
		t.Fatalf("pusty dziennik: %+v", a)
	}
}

// sim to symulowany dziennik i czytnik.
type sim struct {
	info     Info
	drained  time.Time
	lastRead uint64
	now      time.Time
}

func newWatcher(s *sim, buf *bytes.Buffer, warns *[]string) *Watcher {
	w := &Watcher{
		Info: func(string) (Info, error) { return s.info, nil },
		Channels: []Channel{{Name: "Security",
			LastDrained: func() time.Time { return s.drained },
			LastRead:    func() (uint64, bool) { return s.lastRead, s.lastRead > 0 }}},
		Log:    slog.New(slog.NewTextHandler(buf, nil)),
		Warn:   func(m string) { *warns = append(*warns, m) },
		WarnAt: 0.5, AlarmAt: 0.8,
		now: func() time.Time { return s.now },
	}
	return w
}

// write dopisuje n rekordów do pełnego dziennika (najstarsze są nadpisywane).
func (s *sim) write(n uint64) {
	s.info.Oldest += n
}

func TestCaughtUpAgentWithFilterNoAlarm(t *testing.T) {
	s := &sim{info: Info{Records: 10000, Oldest: 1, FileSize: 20 << 20, MaxSize: 20 << 20}, now: time.Now()}
	var buf bytes.Buffer
	var warns []string
	w := newWatcher(s, &buf, &warns)
	s.lastRead = 50 // ostatnie PASUJĄCE zdarzenie dawno temu – filtr odrzuca resztę
	for range 10 {
		s.now = s.now.Add(time.Minute)
		s.write(3000) // dziennik zawija się kilka razy
		s.drained = s.now.Add(-time.Second)
		w.Check()
	}
	if len(warns) != 0 || strings.Contains(buf.String(), "level=ERROR") {
		t.Fatalf("fałszywy alarm dla agenta na bieżąco:\n%v\n%s", warns, buf.String())
	}
}

func TestStuckAgentWarnsThenAlarmsThenLoses(t *testing.T) {
	s := &sim{info: Info{Records: 10000, Oldest: 1, FileSize: 20 << 20, MaxSize: 20 << 20}, now: time.Now()}
	var buf bytes.Buffer
	var warns []string
	w := newWatcher(s, &buf, &warns)

	s.drained = s.now
	s.now = s.now.Add(time.Second)
	w.Check() // agent na bieżąco: pozycja = najnowszy (10000)

	// Serwer niedostępny: czytnik stoi, dziennik rośnie o 1000/min.
	steps := []struct {
		wantWarns int
		want      string
	}{
		{0, ""}, {0, ""}, {0, ""}, {0, ""},
		{1, "50%"},       // 5000 niewysłanych = 50%
		{1, ""}, {1, ""}, // bez powtórzeń na tym samym poziomie
		{2, "80%"}, // alarm
		{2, ""}, {2, ""},
		{3, "nadpisał"}, // 11 000 > pojemność: utrata
		{4, "nadpisał"}, // kolejny zakres
	}
	for i, st := range steps {
		s.now = s.now.Add(time.Minute)
		s.write(1000)
		w.Check()
		if len(warns) != st.wantWarns || (st.want != "" && !strings.Contains(warns[len(warns)-1], st.want)) {
			t.Fatalf("krok %d: ostrzeżenia %d (chcę %d z %q):\n%s", i+1, len(warns), st.wantWarns, st.want, strings.Join(warns, "\n"))
		}
	}
	if !strings.Contains(warns[1], "szacunkowo za") {
		t.Errorf("alarm powinien podawać szacowany czas: %q", warns[1])
	}
	if !strings.Contains(warns[2], "10001–11000") {
		t.Errorf("zakres utraty: %q", warns[2])
	}

	// Łączność wraca: agent nadrabia.
	s.drained = s.now.Add(time.Second)
	s.now = s.now.Add(time.Minute)
	w.Check()
	if !strings.Contains(buf.String(), "odrobiona") {
		t.Errorf("brak informacji o odrobieniu zaległości:\n%s", buf.String())
	}
}

func TestAdviceForSmallSecurityLog(t *testing.T) {
	s := &sim{info: Info{Records: 100, Oldest: 1, FileSize: 1 << 20, MaxSize: 20 << 20, Retention: true}, now: time.Now()}
	var buf bytes.Buffer
	var warns []string
	w := newWatcher(s, &buf, &warns)
	w.Check()
	w.Check()
	out := buf.String()
	if strings.Count(out, "dziennik Security jest mały") != 1 || strings.Count(out, "nie nadpisuj") != 1 {
		t.Fatalf("podpowiedź powinna pojawić się raz:\n%s", out)
	}
}
