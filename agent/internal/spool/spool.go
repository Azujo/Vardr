// Package spool to dyskowy bufor paczek agenta na czas braku łączności
// z serwerem (roadmapa, sekcja 7: bufor offline).
//
// Bez bufora jedynym buforem jest dziennik Windows: przy dłuższej przerwie
// Windows nadpisuje niewysłane zdarzenia. Z buforem paczka, której nie udało
// się wysłać od razu, jest zapisywana na dysk (fsync) i od tej chwili uważana
// za bezpieczną – agent zapisuje pozycję odczytu i czyta dalej, a osobna
// gorutyna dosyła paczki z dysku, najstarsze najpierw.
//
// Rozmiar bufora jest ograniczony (MaxBytes) i nigdy nie zajmuje ostatnich
// MinFreeBytes wolnego miejsca na dysku. Po zapełnieniu:
//   - OnFull = "pause" (domyślnie): nowe paczki czekają jak bez bufora –
//     odczyt staje, zdarzenia zostają w dzienniku Windows;
//   - OnFull = "drop_oldest": usuwane są najstarsze paczki z bufora
//     (strata liczona i zgłaszana w heartbeacie).
package spool

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"siem/internal/contract"
)

// Zachowanie po zapełnieniu bufora.
const (
	OnFullPause      = "pause"
	OnFullDropOldest = "drop_oldest"
)

// Next to właściwy nadawca (implementuje shipper.HTTPSender).
type Next interface {
	// TrySend: jedna próba; done = paczka przyjęta albo ostatecznie
	// odłożona (kwarantanna); false = błąd przejściowy.
	TrySend(ctx context.Context, b *contract.Batch) (done bool, err error)
	// Send ponawia do skutku (albo anulowania kontekstu).
	Send(ctx context.Context, b *contract.Batch) error
}

// Stats to stan bufora dla statusu agenta.
type Stats struct {
	Batches       int       `json:"batches"`
	Bytes         int64     `json:"bytes"`
	MaxBytes      int64     `json:"max_bytes"`
	OnFull        string    `json:"on_full"`
	OldestAt      time.Time `json:"oldest_at,omitzero"`
	Spooled       int64     `json:"spooled_events"`  // zdarzenia zapisane w buforze od startu
	Dropped       int64     `json:"dropped_events"`  // zdarzenia usunięte z pełnego bufora (drop_oldest)
	DroppedTotal  int64     `json:"dropped_batches"` // paczki usunięte z pełnego bufora
	Full          bool      `json:"full"`
	Disabled      bool      `json:"disabled"`
	LastError     string    `json:"last_error,omitempty"`
	LastErrorTime time.Time `json:"last_error_at,omitzero"`
}

// Spool to bufor dyskowy przed nadawcą.
type Spool struct {
	Dir  string
	Next Next
	Log  *slog.Logger
	// FreeSpace zwraca wolne miejsce na dysku katalogu (nil = bez sprawdzania).
	FreeSpace func(dir string) (uint64, error)

	maxBytes     atomic.Int64
	minFreeBytes atomic.Int64
	onFull       atomic.Value // string

	mu      sync.Mutex
	files   []entry // od najstarszego
	bytes   int64
	kick    chan struct{}
	spooled atomic.Int64
	dropped atomic.Int64
	dropB   atomic.Int64
	full    atomic.Bool
	lastErr atomic.Value // errInfo
}

type entry struct {
	name   string
	size   int64
	events int
	at     time.Time
}

type errInfo struct {
	msg string
	at  time.Time
}

// Open wczytuje bufor z katalogu (paczki z poprzedniego uruchomienia zostają).
func Open(dir string, next Next, log *slog.Logger) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{Dir: dir, Next: next, Log: log, kick: make(chan struct{}, 1)}
	s.onFull.Store(OnFullPause)
	s.minFreeBytes.Store(1 << 30)
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, de := range des {
		name := de.Name()
		if strings.HasSuffix(name, ".tmp") {
			_ = os.Remove(filepath.Join(dir, name)) // niedokończony zapis
			continue
		}
		e, ok := parseName(name)
		if !ok {
			continue
		}
		if fi, err := de.Info(); err == nil {
			e.size = fi.Size()
		}
		s.files = append(s.files, e)
		s.bytes += e.size
	}
	slices.SortFunc(s.files, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	return s, nil
}

// Configure ustawia limit (0 = bufor wyłączony), zachowanie po zapełnieniu
// i rezerwę wolnego miejsca. Bezpieczne w trakcie pracy.
func (s *Spool) Configure(maxBytes int64, onFull string, minFreeBytes int64) {
	s.maxBytes.Store(maxBytes)
	if onFull != OnFullDropOldest {
		onFull = OnFullPause
	}
	s.onFull.Store(onFull)
	s.minFreeBytes.Store(minFreeBytes)
}

// Stats zwraca stan bufora.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	st := Stats{Batches: len(s.files), Bytes: s.bytes}
	if len(s.files) > 0 {
		st.OldestAt = s.files[0].at
	}
	s.mu.Unlock()
	st.MaxBytes = s.maxBytes.Load()
	st.OnFull = s.onFull.Load().(string)
	st.Spooled, st.Dropped, st.DroppedTotal = s.spooled.Load(), s.dropped.Load(), s.dropB.Load()
	st.Full = s.full.Load()
	st.Disabled = st.MaxBytes <= 0
	if e, ok := s.lastErr.Load().(errInfo); ok {
		st.LastError, st.LastErrorTime = e.msg, e.at
	}
	return st
}

func (s *Spool) empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.files) == 0
}

// Send przekazuje paczkę: gdy bufor jest pusty – od razu do serwera (jedna
// próba), a przy błędzie przejściowym albo niepustym buforze (kolejność) –
// do bufora. Zwraca nil, gdy paczka jest przyjęta albo bezpieczna na dysku.
func (s *Spool) Send(ctx context.Context, b *contract.Batch) error {
	if s.maxBytes.Load() <= 0 {
		return s.Next.Send(ctx, b) // bufor wyłączony – jak dawniej
	}
	if s.empty() {
		done, err := s.Next.TrySend(ctx, b)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	for {
		err := s.write(b)
		if err == nil {
			s.full.Store(false)
			s.signal()
			return nil
		}
		if !errors.Is(err, errFull) {
			// Zapis na dysk nieudany – zachowanie jak bez bufora.
			s.setErr(err)
			s.Log.Error("zapis paczki do bufora dyskowego nieudany – czekam na serwer", "err", err)
			return s.Next.Send(ctx, b)
		}
		if !s.full.Swap(true) {
			s.Log.Warn("bufor dyskowy pełny", "on_full", s.onFull.Load(), "bytes", s.Stats().Bytes, "limit", s.maxBytes.Load())
		}
		if s.onFull.Load() == OnFullDropOldest && s.dropOldest() {
			continue
		}
		// pause: nowa paczka czeka na serwer; czytniki stoją, zdarzenia
		// zostają w dzienniku Windows.
		return s.Next.Send(ctx, b)
	}
}

var errFull = errors.New("bufor pełny")

func (s *Spool) write(b *contract.Batch) error {
	data, err := encode(b)
	if err != nil {
		return err
	}
	size := int64(len(data))
	s.mu.Lock()
	over := s.bytes+size > s.maxBytes.Load()
	s.mu.Unlock()
	if over {
		return errFull
	}
	if s.FreeSpace != nil {
		if free, err := s.FreeSpace(s.Dir); err == nil && int64(free)-size < s.minFreeBytes.Load() {
			return errFull
		}
	}
	now := time.Now().UTC()
	e := entry{name: fmt.Sprintf("%020d-%d-%s.batch", now.UnixNano(), len(b.Events), b.BatchID), size: size, events: len(b.Events), at: now}
	path := filepath.Join(s.Dir, e.name)
	if err := writeSync(path, data); err != nil {
		return err
	}
	s.mu.Lock()
	s.files = append(s.files, e)
	s.bytes += size
	s.mu.Unlock()
	s.spooled.Add(int64(len(b.Events)))
	return nil
}

// dropOldest usuwa najstarszą paczkę, która nie jest właśnie wysyłana.
func (s *Spool) dropOldest() bool {
	s.mu.Lock()
	if len(s.files) < 2 { // pierwszą może właśnie wysyłać Run
		s.mu.Unlock()
		return false
	}
	e := s.files[1]
	s.files = slices.Delete(s.files, 1, 2)
	s.bytes -= e.size
	s.mu.Unlock()
	_ = os.Remove(filepath.Join(s.Dir, e.name))
	s.dropped.Add(int64(e.events))
	s.dropB.Add(1)
	s.Log.Error("bufor pełny – usunięto najstarszą paczkę (utrata zdarzeń)", "events", e.events, "spooled_at", e.at)
	return true
}

func (s *Spool) signal() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *Spool) setErr(err error) { s.lastErr.Store(errInfo{msg: err.Error(), at: time.Now().UTC()}) }

// Run dosyła paczki z bufora (najstarsze najpierw) do anulowania kontekstu.
func (s *Spool) Run(ctx context.Context) {
	for {
		s.mu.Lock()
		var e entry
		ok := len(s.files) > 0
		if ok {
			e = s.files[0]
		}
		s.mu.Unlock()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-s.kick:
				continue
			}
		}
		path := filepath.Join(s.Dir, e.name)
		b, err := readBatch(path)
		if err != nil {
			// Uszkodzony plik (np. dysk): odkładamy obok, żeby nie blokował kolejki.
			s.setErr(err)
			s.Log.Error("paczka w buforze nieczytelna – przeniesiona do bad/", "file", e.name, "err", err)
			_ = os.MkdirAll(filepath.Join(s.Dir, "bad"), 0o700)
			_ = os.Rename(path, filepath.Join(s.Dir, "bad", e.name))
		} else if err := s.Next.Send(ctx, b); err != nil {
			return // anulowanie – paczka zostaje w buforze
		} else {
			_ = os.Remove(path)
		}
		s.mu.Lock()
		if len(s.files) > 0 && s.files[0].name == e.name {
			s.files = s.files[1:]
			s.bytes -= e.size
		}
		empty := len(s.files) == 0
		s.mu.Unlock()
		if empty {
			s.full.Store(false)
			s.Log.Info("bufor dyskowy opróżniony – wszystkie paczki dosłane")
		}
	}
}

func parseName(name string) (entry, bool) {
	if !strings.HasSuffix(name, ".batch") {
		return entry{}, false
	}
	parts := strings.SplitN(strings.TrimSuffix(name, ".batch"), "-", 3)
	if len(parts) != 3 {
		return entry{}, false
	}
	ns, err1 := strconv.ParseInt(parts[0], 10, 64)
	n, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return entry{}, false
	}
	return entry{name: name, events: n, at: time.Unix(0, ns).UTC()}, true
}

func encode(b *contract.Batch) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func readBatch(path string) (*contract.Batch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var b contract.Batch
	if err := json.NewDecoder(zr).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// writeSync zapisuje plik trwale: tmp + fsync + rename.
func writeSync(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
