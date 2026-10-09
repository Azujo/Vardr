package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"siem/internal/reprocess"
	"siem/panel/internal/api/store"
	"siem/panel/internal/events"
)

type memQuarantine struct {
	mu       sync.Mutex
	jobs     []store.QuarantineJob
	outcomes map[string]store.QuarantineOutcome
}

func (m *memQuarantine) CreateQuarantineJob(_ context.Context, by string, _ any, total int) (store.QuarantineJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j := store.QuarantineJob{ID: int64(len(m.jobs) + 1), CreatedBy: by, Status: "running", Total: total}
	m.jobs = append(m.jobs, j)
	return j, nil
}
func (m *memQuarantine) RecordQuarantineOutcomes(_ context.Context, job int64, rec []string, failed map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range rec {
		m.outcomes[id] = store.QuarantineOutcome{EventID: id, JobID: job, Recovered: true}
	}
	for id, r := range failed {
		m.outcomes[id] = store.QuarantineOutcome{EventID: id, JobID: job, Reason: r}
	}
	m.jobs[job-1].Recovered += len(rec)
	m.jobs[job-1].Failed += len(failed)
	return nil
}
func (m *memQuarantine) FinishQuarantineJob(_ context.Context, job int64, msg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[job-1].Status, m.jobs[job-1].Error = "done", msg
	if msg != "" {
		m.jobs[job-1].Status = "failed"
	}
	return nil
}
func (m *memQuarantine) ListQuarantineJobs(context.Context, int) ([]store.QuarantineJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.jobs), nil
}
func (m *memQuarantine) QuarantineOutcomes(_ context.Context, ids []string) (map[string]store.QuarantineOutcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]store.QuarantineOutcome{}
	for _, id := range ids {
		if o, ok := m.outcomes[id]; ok {
			out[id] = o
		}
	}
	return out, nil
}

type fakeQuarantineSource struct{ items []reprocess.Item }

func (f *fakeQuarantineSource) QuarantineOverview(context.Context, events.QuarantineFilter, int) ([]events.QuarantineGroup, []events.QuarantineEntry, uint64, error) {
	var es []events.QuarantineEntry
	for _, it := range f.items {
		es = append(es, events.QuarantineEntry{EventID: it.EventID, Source: it.Source, Raw: it.Raw, Reason: "zły JSON"})
	}
	es = append(es, events.QuarantineEntry{EventID: "rej-1", Source: "windows.security", Reason: "zapis do ClickHouse odrzucony"})
	return []events.QuarantineGroup{{Source: "syslog:udp", Reason: "zły JSON", Count: uint64(len(f.items))}}, es, uint64(len(es)), nil
}
func (f *fakeQuarantineSource) QuarantineItems(_ context.Context, flt events.QuarantineFilter, limit int) ([]reprocess.Item, error) {
	var out []reprocess.Item
	for _, it := range f.items {
		if flt.Source == "" || strings.HasPrefix(it.Source, flt.Source) {
			out = append(out, it)
		}
	}
	return out[:min(limit, len(out))], nil
}

func TestQuarantineReprocessAPI(t *testing.T) {
	e := newEnv(t)
	mq := &memQuarantine{outcomes: map[string]store.QuarantineOutcome{}}
	src := &fakeQuarantineSource{}
	for i := range 1200 {
		raw := `{"ok":true}`
		if i%100 == 0 {
			raw = "nadal zepsute"
		}
		src.items = append(src.items, reprocess.Item{EventID: "c:syslog:g0:" + strconv.Itoa(i),
			AgentID: "c", Source: "syslog:udp", Raw: raw})
	}
	var calls int
	var mu sync.Mutex
	release := make(chan struct{})
	// Udawany normalizator: odzyskuje wszystko poza „nadal zepsute”; pierwsza część raz zawodzi (ponowienie).
	request := func(_ context.Context, data []byte) ([]byte, error) {
		<-release
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			return json.Marshal(reprocess.Reply{Error: "chwilowy błąd publikacji"})
		}
		var req reprocess.Request
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		var rep reprocess.Reply
		for _, it := range req.Items {
			if it.Raw == "nadal zepsute" {
				rep.Failed = append(rep.Failed, reprocess.Failure{EventID: it.EventID, Reason: "niepoprawny JSON"})
			} else {
				rep.Recovered = append(rep.Recovered, it.EventID)
			}
		}
		return json.Marshal(rep)
	}
	q := &Quarantine{Store: mq, Source: src, Request: request, Log: slog.New(slog.DiscardHandler)}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Quarantine: q}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleAnalyst, "haslo-oli-12345", false)
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	analyst, admin := e.client("10.0.0.1"), e.client("10.0.0.2")
	analyst.login("ola", "haslo-oli-12345")
	admin.login("adam", "haslo-adama-123")

	code, out, _ := analyst.do("GET", "/api/v1/quarantine?hours=24", nil)
	entries, _ := out["entries"].([]any)
	if code != 200 || len(entries) != 1201 || entries[1200].(map[string]any)["supported"] != false {
		t.Fatalf("lista: %d %d", code, len(entries))
	}
	if code, _, _ := analyst.do("POST", "/api/v1/quarantine/reprocess", map[string]any{"hours": 24}); code != 403 {
		t.Fatalf("zlecenie przez analityka: %d", code)
	}
	code, out, _ = admin.do("POST", "/api/v1/quarantine/reprocess", map[string]any{"hours": 24, "source": "syslog:"})
	if code != 202 {
		t.Fatalf("zlecenie: %d %v", code, out)
	}
	// Drugie zlecenie w trakcie pierwszego – odmowa.
	if code, out, _ := admin.do("POST", "/api/v1/quarantine/reprocess", map[string]any{"hours": 24}); code != 409 {
		t.Fatalf("równoległe zlecenie: %d %v", code, out)
	}
	close(release)
	deadline := time.Now().Add(20 * time.Second)
	for {
		jobs, _ := mq.ListQuarantineJobs(context.Background(), 1)
		if jobs[0].Status != "running" {
			if jobs[0].Status != "done" || jobs[0].Total != 1200 || jobs[0].Recovered != 1188 || jobs[0].Failed != 12 {
				t.Fatalf("zlecenie: %+v", jobs[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("zlecenie nie skończyło się")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if calls != 4 { // 3 części po 500/500/200 + jedno ponowienie
		t.Fatalf("żądania do normalizatora: %d", calls)
	}
	// Ponowne zlecenie obejmuje tylko wpisy nadal błędne.
	for q.running.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	code, out, _ = admin.do("POST", "/api/v1/quarantine/reprocess", map[string]any{"hours": 24})
	if job, _ := out["job"].(map[string]any); code != 202 || job["total"] != float64(12) {
		t.Fatalf("ponowne zlecenie: %d %v", code, out)
	}
	if !slices.Contains(e.st.actions(), "quarantine_reprocess") {
		t.Fatal("brak wpisu audytu")
	}
	for q.running.Load() {
		time.Sleep(10 * time.Millisecond)
	}
}
