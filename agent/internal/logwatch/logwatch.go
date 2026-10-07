// Package logwatch pilnuje, żeby dziennik Windows nie nadpisał zdarzeń,
// których agent jeszcze nie wysłał (etap 1.5, ustalenie K3).
//
// Dziennik Windows jest jedynym buforem agenta: gdy serwer jest niedostępny,
// agent przestaje czytać, a niewysłane zdarzenia czekają w dzienniku. Po
// jego zapełnieniu Windows nadpisuje najstarsze wpisy. Watcher co minutę
// porównuje pozycję agenta z zawartością dziennika i ostrzega, zanim do
// tego dojdzie (oraz zgłasza, gdy już doszło).
package logwatch

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"
)

// Info to stan dziennika odczytany z Windows (EvtGetLogInfo i konfiguracja kanału).
type Info struct {
	Records  uint64 // liczba rekordów w dzienniku
	Oldest   uint64 // numer najstarszego rekordu
	FileSize uint64 // bieżący rozmiar pliku (B)
	MaxSize  uint64 // maksymalny rozmiar (B)
	// Retention: true = „nie nadpisuj” (po zapełnieniu dziennik przestaje
	// przyjmować zdarzenia); false = nadpisywanie najstarszych (domyślnie).
	Retention  bool
	AutoBackup bool // archiwizacja pełnego dziennika do pliku
}

// Newest zwraca numer najnowszego rekordu (0 dla pustego dziennika).
func (i Info) Newest() uint64 {
	if i.Records == 0 {
		return 0
	}
	return i.Oldest + i.Records - 1
}

// Capacity szacuje, ile rekordów zmieści dziennik po zapełnieniu.
func (i Info) Capacity() uint64 {
	if i.Records == 0 || i.FileSize == 0 || i.MaxSize <= i.FileSize {
		return i.Records
	}
	return uint64(float64(i.Records) * float64(i.MaxSize) / float64(i.FileSize))
}

// Assessment to ocena ryzyka dla kanału.
type Assessment struct {
	// Unread: rekordy nowsze niż pozycja agenta (górne oszacowanie
	// niewysłanych – część może nie pasować do filtra Event ID).
	Unread uint64
	// Risk: część pojemności dziennika zajęta przez niewysłane (0–1).
	Risk float64
	// Lost: rekordy nadpisane, zanim agent do nich dotarł (górne oszacowanie).
	Lost uint64
	// TimeLeft: szacowany czas do nadpisania niewysłanych przy obecnym
	// tempie zapisu (0 = brak danych o tempie).
	TimeLeft time.Duration
}

// Assess ocenia ryzyko. pos to numer rekordu, do którego agent na pewno
// doczytał dziennik; rate to tempo zapisu do dziennika (rekordy/s).
func Assess(info Info, pos uint64, rate float64) Assessment {
	var a Assessment
	if info.Records == 0 {
		return a
	}
	if info.Oldest > pos+1 {
		a.Lost = info.Oldest - pos - 1
		pos = info.Oldest - 1
	}
	if newest := info.Newest(); newest > pos {
		a.Unread = newest - pos
	}
	capacity := info.Capacity()
	if capacity > 0 {
		a.Risk = math.Min(1, float64(a.Unread)/float64(capacity))
	}
	if rate > 0 && a.Unread > 0 && capacity > a.Unread {
		a.TimeLeft = time.Duration(float64(capacity-a.Unread) / rate * float64(time.Second))
	}
	return a
}

// Channel to obserwowany kanał.
type Channel struct {
	Name string
	// LastDrained: kiedy czytnik ostatnio odczytał wszystko, co było
	// w subskrypcji (był na bieżąco).
	LastDrained func() time.Time
	// LastRead: numer ostatniego przeczytanego rekordu pasującego do filtra.
	LastRead func() (uint64, bool)
}

// Watcher okresowo sprawdza kanały.
type Watcher struct {
	Info     func(channel string) (Info, error)
	Channels []Channel
	Log      *slog.Logger
	// Warn (opcjonalne) zapisuje ostrzeżenie w statusie agenta.
	Warn     func(msg string)
	Interval time.Duration
	// Progi części dziennika zajętej przez niewysłane zdarzenia.
	WarnAt, AlarmAt float64

	state map[string]*chanState
	now   func() time.Time
}

type chanState struct {
	watermark  uint64 // najnowszy rekord z chwili, gdy agent był na bieżąco
	checkedAt  time.Time
	newest     uint64
	level      int // 0 OK, 1 ostrzeżenie, 2 alarm
	lostUpTo   uint64
	adviceDone bool
}

// Run sprawdza kanały co Interval do zakończenia ctx.
func (w *Watcher) Run(ctx context.Context) {
	if w.Interval <= 0 {
		w.Interval = time.Minute
	}
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
		w.Check()
		t.Reset(w.Interval)
	}
}

// Check wykonuje jedno sprawdzenie wszystkich kanałów.
func (w *Watcher) Check() {
	if w.state == nil {
		w.state = map[string]*chanState{}
	}
	if w.now == nil {
		w.now = time.Now
	}
	for _, ch := range w.Channels {
		info, err := w.Info(ch.Name)
		if err != nil {
			w.Log.Debug("odczyt stanu dziennika nieudany", "channel", ch.Name, "err", err)
			continue
		}
		w.check(ch, info)
	}
}

func (w *Watcher) check(ch Channel, info Info) {
	now := w.now()
	st := w.state[ch.Name]
	first := st == nil
	if first {
		st = &chanState{}
		w.state[ch.Name] = st
	}
	newest := info.Newest()

	// Tempo zapisu do dziennika (rekordy/s) z różnicy między sprawdzeniami.
	var rate float64
	if !first && newest >= st.newest && now.After(st.checkedAt) {
		rate = float64(newest-st.newest) / now.Sub(st.checkedAt).Seconds()
	}

	// Pozycja agenta. Czytnik widzi tylko zdarzenia pasujące do filtra, więc
	// numer ostatniego przeczytanego może być daleko w tyle, mimo że agent
	// jest na bieżąco. Jeśli czytnik opróżnił subskrypcję od poprzedniego
	// sprawdzenia, przeczytał wszystko do (prawie) najnowszego rekordu.
	if d := ch.LastDrained(); !d.IsZero() && (first || d.After(st.checkedAt)) {
		st.watermark = newest
	}
	pos := st.watermark
	if r, ok := ch.LastRead(); ok && r > pos {
		pos = r
	}
	if pos == 0 && first {
		pos = newest // brak danych o pozycji – nie zgłaszamy fałszywej straty
	}
	st.checkedAt, st.newest = now, newest

	a := Assess(info, pos, rate)
	w.report(ch.Name, info, a, st)
	if !st.adviceDone {
		st.adviceDone = true
		w.advise(ch.Name, info)
	}
}

func (w *Watcher) report(name string, info Info, a Assessment, st *chanState) {
	if a.Lost > 0 && info.Oldest-1 > st.lostUpTo {
		from := max(st.lostUpTo+1, info.Oldest-a.Lost)
		msg := fmt.Sprintf("kanał %s: dziennik Windows nadpisał do %d rekordów (%d–%d), zanim agent je wysłał – możliwa luka w danych",
			name, info.Oldest-from, from, info.Oldest-1)
		w.Log.Error(msg, "channel", name, "eventlog", true)
		w.warn(msg)
		st.lostUpTo = info.Oldest - 1
	}

	level := 0
	switch {
	case a.Risk >= w.AlarmAt:
		level = 2
	case a.Risk >= w.WarnAt:
		level = 1
	}
	attrs := []any{"channel", name, "unsent_records", a.Unread, "log_capacity_records", info.Capacity(),
		"risk", math.Round(a.Risk*100) / 100}
	if a.TimeLeft > 0 {
		attrs = append(attrs, "time_left", a.TimeLeft.Round(time.Minute))
	}
	switch {
	case level > st.level:
		msg := fmt.Sprintf("kanał %s: niewysłane zdarzenia zajmują %.0f%% dziennika Windows – przy dłuższym braku łączności zostaną nadpisane",
			name, a.Risk*100)
		if a.TimeLeft > 0 {
			msg += fmt.Sprintf(" (szacunkowo za %s)", humanDuration(a.TimeLeft))
		}
		if level == 2 {
			w.Log.Error(msg, append(attrs, "eventlog", true)...)
		} else {
			w.Log.Warn(msg, append(attrs, "eventlog", true)...)
		}
		w.warn(msg)
	case level == 0 && st.level > 0:
		w.Log.Info(fmt.Sprintf("kanał %s: zaległość w dzienniku Windows odrobiona", name), attrs...)
	}
	st.level = level
}

// advise jednorazowo podpowiada zmianę rozmiaru dziennika (GPO).
func (w *Watcher) advise(name string, info Info) {
	const mb = 1 << 20
	if info.Retention {
		w.Log.Warn(fmt.Sprintf("kanał %s: dziennik ustawiony na „nie nadpisuj” – po zapełnieniu Windows przestanie zapisywać nowe zdarzenia", name),
			"channel", name, "max_size_mb", info.MaxSize/mb, "eventlog", true)
	}
	if name == "Security" && info.MaxSize > 0 && info.MaxSize < 128*mb {
		w.Log.Warn("dziennik Security jest mały – przy przerwie w łączności zdarzenia mogą zostać nadpisane; zalecane min. 128 MB na stacjach i 512 MB–1 GB na serwerach i kontrolerach domeny (GPO, patrz README)",
			"channel", name, "max_size_mb", info.MaxSize/mb, "eventlog", true)
	}
}

func (w *Watcher) warn(msg string) {
	if w.Warn != nil {
		w.Warn(msg)
	}
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "mniej niż minutę"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1f h", d.Hours())
	}
	return fmt.Sprintf("%.0f dni", d.Hours()/24)
}
