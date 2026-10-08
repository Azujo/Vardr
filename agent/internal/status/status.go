// Package status zbiera bieżący stan agenta i zapisuje go do pliku
// status.json w katalogu stanu (dostępnym tylko dla administratorów).
// Z pliku korzysta polecenie „siem_agent status”; docelowo te same dane
// trafią w heartbeacie do panelu.
package status

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

// Stany kanału.
const (
	ChannelStarting     = "starting"
	ChannelOK           = "ok"
	ChannelNotFound     = "not_found"
	ChannelAccessDenied = "access_denied"
	ChannelError        = "error"
)

// Status to migawka stanu agenta.
type Status struct {
	UpdatedAt time.Time `json:"updated_at"`
	Version   string    `json:"version"`
	AgentID   string    `json:"agent_id"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`

	Server   ServerStatus    `json:"server"`
	Channels []ChannelStatus `json:"channels"`
	Counters Counters        `json:"counters"`
	Limits   map[string]any  `json:"limits"`
	Throttle ThrottleStatus  `json:"throttle"`
	Process  ProcessStatus   `json:"process"`
	Config   ConfigStatus    `json:"config"`
	Buffer   *BufferStatus   `json:"buffer,omitempty"`
	Clock    ClockStatus     `json:"clock"`
	Warnings []string        `json:"warnings,omitempty"`
}

// BufferStatus to stan dyskowego bufora paczek.
type BufferStatus struct {
	Batches       int       `json:"batches"`
	Bytes         int64     `json:"bytes"`
	MaxBytes      int64     `json:"max_bytes"`
	OnFull        string    `json:"on_full"`
	OldestAt      time.Time `json:"oldest_at,omitzero"`
	Spooled       int64     `json:"spooled_events"`
	Dropped       int64     `json:"dropped_events"`
	Full          bool      `json:"full"`
	Disabled      bool      `json:"disabled"`
	LastError     string    `json:"last_error,omitempty"`
	LastErrorTime time.Time `json:"last_error_at,omitzero"`
}

// ClockStatus to zegar komputera względem serwera Heimdalla i stan usługi
// czasu Windows (W32Time).
type ClockStatus struct {
	// OffsetMs: zegar agenta minus zegar serwera (ms); dodatnie = agent się spieszy.
	OffsetMs      int64     `json:"offset_ms"`
	UncertaintyMs int64     `json:"uncertainty_ms"`
	MeasuredAt    time.Time `json:"measured_at,omitzero"`
	TimeService   string    `json:"time_service,omitempty"` // running | stopped | disabled | missing | unknown
}

type ServerStatus struct {
	URL            string    `json:"url"`
	LastAcceptedAt time.Time `json:"last_accepted_at,omitzero"`
	LastError      string    `json:"last_error,omitempty"`
	LastErrorAt    time.Time `json:"last_error_at,omitzero"`
	// Healthy: ostatnia próba wysyłki zakończyła się powodzeniem.
	Healthy bool `json:"healthy"`
}

type ChannelStatus struct {
	Name         string        `json:"name"`
	State        string        `json:"state"`
	Error        string        `json:"error,omitempty"`
	LastRecordID uint64        `json:"last_record_id,omitempty"`
	LastReadAt   time.Time     `json:"last_read_at,omitzero"`
	LastLag      time.Duration `json:"last_lag_ns,omitempty"`
}

type Counters struct {
	Read        int64 `json:"read"`
	Filtered    int64 `json:"filtered"`
	Accepted    int64 `json:"accepted"`
	Truncated   int64 `json:"truncated"`
	Quarantined int64 `json:"quarantined"`
	Retries     int64 `json:"retries"`
}

// ConfigStatus mówi, skąd pochodzi konfiguracja kanałów i limitów.
type ConfigStatus struct {
	Source    string    `json:"source"` // local (agent.yaml) | panel (grupa)
	Group     string    `json:"group,omitempty"`
	Version   string    `json:"version,omitempty"` // wersja z panelu (porównywana w Huginn)
	AppliedAt time.Time `json:"applied_at,omitzero"`
}

type ThrottleStatus struct {
	EPS       time.Duration `json:"eps_ns"`
	Bandwidth time.Duration `json:"bandwidth_ns"`
}

type ProcessStatus struct {
	CPUTime    time.Duration `json:"cpu_time_ns"`
	HeapMB     float64       `json:"heap_mb"`
	SysMB      float64       `json:"sys_mb"`
	Goroutines int           `json:"goroutines"`
	MaxProcs   int           `json:"max_procs"`
}

// Tracker przechowuje stan aktualizowany przez komponenty agenta.
type Tracker struct {
	mu       sync.Mutex
	s        Status
	channels map[string]*ChannelStatus
	probes   []func(*Status)
	named    map[string]func(*Status)
	now      func() time.Time
}

// NewTracker tworzy tracker.
func NewTracker(version, agentID, serverURL string, limits map[string]any) *Tracker {
	now := time.Now().UTC()
	return &Tracker{
		s: Status{Version: version, AgentID: agentID, PID: os.Getpid(), StartedAt: now,
			Server: ServerStatus{URL: serverURL}, Limits: limits},
		channels: map[string]*ChannelStatus{},
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// AddProbe rejestruje funkcję uzupełniającą migawkę (np. liczniki, czas dławienia).
func (t *Tracker) AddProbe(p func(*Status)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.probes = append(t.probes, p)
}

func (t *Tracker) channel(name string) *ChannelStatus {
	c, ok := t.channels[name]
	if !ok {
		c = &ChannelStatus{Name: name, State: ChannelStarting}
		t.channels[name] = c
	}
	return c
}

// ChannelState ustawia stan kanału (np. po błędzie subskrypcji).
func (t *Tracker) ChannelState(name, state, errMsg string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.channel(name)
	c.State, c.Error = state, errMsg
}

// ChannelRead odnotowuje odczyt zdarzenia z kanału.
func (t *Tracker) ChannelRead(name string, recordID uint64, readAt time.Time, lag time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.channel(name)
	c.State, c.Error = ChannelOK, ""
	c.LastRecordID, c.LastReadAt, c.LastLag = recordID, readAt, lag
}

// Warn dodaje trwałe ostrzeżenie widoczne w statusie (maks. 20 ostatnich).
func (t *Tracker) Warn(msg string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	w := t.now().Local().Format("2006-01-02 15:04:05") + " " + msg
	t.s.Warnings = append(t.s.Warnings, w)
	if n := len(t.s.Warnings); n > 20 {
		t.s.Warnings = t.s.Warnings[n-20:]
	}
}

// SendOK odnotowuje przyjęcie paczki przez serwer.
func (t *Tracker) SendOK() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.s.Server.LastAcceptedAt = t.now()
	t.s.Server.Healthy = true
}

// SendFailed odnotowuje nieudaną próbę wysyłki.
func (t *Tracker) SendFailed(errMsg string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.s.Server.LastError, t.s.Server.LastErrorAt = errMsg, t.now()
	t.s.Server.Healthy = false
}

// Snapshot zwraca kopię bieżącego stanu.
func (t *Tracker) Snapshot() Status {
	t.mu.Lock()
	s := t.s
	s.Warnings = append([]string{}, t.s.Warnings...)
	s.UpdatedAt = t.now()
	s.Channels = make([]ChannelStatus, 0, len(t.channels))
	for _, c := range t.channels {
		s.Channels = append(s.Channels, *c)
	}
	probes := append([]func(*Status){}, t.probes...)
	for _, p := range t.named {
		probes = append(probes, p)
	}
	t.mu.Unlock()

	sort.Slice(s.Channels, func(i, j int) bool { return s.Channels[i].Name < s.Channels[j].Name })
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.Process.HeapMB = float64(ms.HeapAlloc) / (1 << 20)
	s.Process.SysMB = float64(ms.Sys) / (1 << 20)
	s.Process.Goroutines = runtime.NumGoroutine()
	s.Process.MaxProcs = runtime.GOMAXPROCS(0)
	for _, p := range probes {
		p(&s)
	}
	return s
}

// FileName to nazwa pliku statusu w katalogu stanu.
const FileName = "status.json"

// Run zapisuje migawkę co interval aż do anulowania kontekstu (i raz na końcu).
func (t *Tracker) Run(ctx context.Context, dir string, interval time.Duration) {
	path := filepath.Join(dir, FileName)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		_ = Write(path, t.Snapshot())
		select {
		case <-tick.C:
		case <-ctx.Done():
			_ = Write(path, t.Snapshot())
			return
		}
	}
}

// Write zapisuje status atomowo.
func Write(path string, s Status) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Read wczytuje status z pliku.
func Read(path string) (Status, error) {
	var s Status
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}

// SetConfig zapisuje źródło i wersję zastosowanej konfiguracji.
func (t *Tracker) SetConfig(c ConfigStatus) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.s.Config = c
}

// SetLimits zapisuje aktualne limity (po zmianie konfiguracji).
func (t *Tracker) SetLimits(limits map[string]any) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.s.Limits = limits
}

// ResetChannels czyści stan kanałów (po zmianie listy kanałów).
func (t *Tracker) ResetChannels() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.channels = map[string]*ChannelStatus{}
}

// SetProbe rejestruje sondę pod nazwą, zastępując poprzednią o tej samej
// nazwie (np. liczniki rdzenia agenta po przeładowaniu konfiguracji).
func (t *Tracker) SetProbe(name string, p func(*Status)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.named == nil {
		t.named = map[string]func(*Status){}
	}
	t.named[name] = p
}

// SetClock zapisuje pomiar odchylenia zegara.
func (t *Tracker) SetClock(offset, uncertainty time.Duration, at time.Time) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.s.Clock.OffsetMs, t.s.Clock.UncertaintyMs, t.s.Clock.MeasuredAt = offset.Milliseconds(), uncertainty.Milliseconds(), at.UTC()
}

// SetTimeService zapisuje stan usługi czasu Windows.
func (t *Tracker) SetTimeService(state string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.s.Clock.TimeService = state
}
