// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"siem/internal/reprocess"
	"siem/panel/internal/api/store"
	"siem/panel/internal/events"
)

// Kwarantanna i jej ponowne przetwarzanie (etap 6d): po poprawce dekodera
// (albo programu) administrator zleca ponowne przetworzenie wybranych wpisów;
// panel wysyła je częściami do normalizatora (NATS request-reply), a wynik
// każdego wpisu zapisuje w Sadze.

// QuarantineStore to zlecenia i wyniki (implementuje store.PG).
type QuarantineStore interface {
	CreateQuarantineJob(ctx context.Context, by string, filter any, total int) (store.QuarantineJob, error)
	RecordQuarantineOutcomes(ctx context.Context, job int64, recovered []string, failed map[string]string) error
	FinishQuarantineJob(ctx context.Context, job int64, errMsg string) error
	ListQuarantineJobs(ctx context.Context, limit int) ([]store.QuarantineJob, error)
	QuarantineOutcomes(ctx context.Context, eventIDs []string) (map[string]store.QuarantineOutcome, error)
}

// QuarantineSource to wpisy kwarantanny w ClickHouse (implementuje events.Searcher).
type QuarantineSource interface {
	QuarantineOverview(ctx context.Context, f events.QuarantineFilter, limit int) ([]events.QuarantineGroup, []events.QuarantineEntry, uint64, error)
	QuarantineItems(ctx context.Context, f events.QuarantineFilter, limit int) ([]reprocess.Item, error)
}

// Quarantine to moduł kwarantanny panelu (opcjonalny).
type Quarantine struct {
	Store  QuarantineStore
	Source QuarantineSource
	// Request wysyła część zlecenia do normalizatora i zwraca odpowiedź;
	// nil – bez NATS (tylko podgląd kwarantanny).
	Request func(ctx context.Context, data []byte) ([]byte, error)
	Log     *slog.Logger

	running atomic.Bool // jedno zlecenie naraz
}

// maxReprocessItems: najwięcej wpisów w jednym zleceniu.
const maxReprocessItems = 10000

func (s *Server) quarantineEnabled(w http.ResponseWriter) bool {
	if s.Quarantine == nil || s.Quarantine.Source == nil {
		writeError(w, http.StatusServiceUnavailable, "quarantine_disabled", "kwarantanna niedostępna (wyszukiwarka zdarzeń wyłączona w konfiguracji siem-api)")
		return false
	}
	return true
}

type quarantineEntryView struct {
	events.QuarantineEntry
	Supported bool                     `json:"supported"`
	Outcome   *store.QuarantineOutcome `json:"outcome,omitempty"`
}

func quarantineFilter(r *http.Request, now time.Time) (events.QuarantineFilter, int, error) {
	q := r.URL.Query()
	hours, _ := strconv.Atoi(q.Get("hours"))
	if hours == 0 {
		hours = 168
	}
	if hours < 1 || hours > 24*90 {
		return events.QuarantineFilter{}, 0, errors.New("okres: od 1 godziny do 90 dni")
	}
	f := events.QuarantineFilter{From: now.Add(-time.Duration(hours) * time.Hour), Source: strings.TrimSpace(q.Get("source")),
		Reason: strings.TrimSpace(q.Get("reason")), Agent: strings.TrimSpace(q.Get("agent"))}
	if len(f.Source) > 200 || len(f.Reason) > 500 || len(f.Agent) > 200 {
		return f, 0, errors.New("za długi filtr")
	}
	return f, hours, nil
}

func (s *Server) listQuarantine(w http.ResponseWriter, r *http.Request) {
	if !s.quarantineEnabled(w) {
		return
	}
	f, _, err := quarantineFilter(r, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_filter", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	groups, entries, total, err := s.Quarantine.Source.QuarantineOverview(ctx, f, 200)
	if err != nil {
		writeError(w, http.StatusBadGateway, "events_failed", err.Error())
		return
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.EventID)
	}
	outcomes, err := s.Quarantine.Store.QuarantineOutcomes(r.Context(), ids)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	views := make([]quarantineEntryView, 0, len(entries))
	for _, e := range entries {
		v := quarantineEntryView{QuarantineEntry: e, Supported: reprocess.Supported(e.Source)}
		if o, ok := outcomes[e.EventID]; ok {
			v.Outcome = &o
		}
		views = append(views, v)
	}
	jobs, err := s.Quarantine.Store.ListQuarantineJobs(r.Context(), 20)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups, "entries": views, "total": total, "jobs": nonNilSlice(jobs),
		"reprocess": s.Quarantine.Request != nil, "running": s.Quarantine.running.Load()})
}

// reprocessQuarantine zleca ponowne przetworzenie wpisów pasujących do
// filtra (bez już odzyskanych). Zlecenie działa w tle; postęp na liście.
func (s *Server) reprocessQuarantine(w http.ResponseWriter, r *http.Request) {
	if !s.quarantineEnabled(w) {
		return
	}
	qm := s.Quarantine
	if qm.Request == nil {
		writeError(w, http.StatusServiceUnavailable, "nats_disabled", "panel nie jest połączony z NATS – ponowne przetwarzanie niedostępne")
		return
	}
	a := current(r)
	var req struct {
		Hours    int      `json:"hours"`
		Source   string   `json:"source"`
		Reason   string   `json:"reason"`
		Agent    string   `json:"agent"`
		EventIDs []string `json:"event_ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Hours < 1 || req.Hours > 24*90 || len(req.Source) > 200 || len(req.Reason) > 500 || len(req.Agent) > 200 || len(req.EventIDs) > 1000 {
		writeError(w, http.StatusBadRequest, "bad_filter", "niepoprawny filtr (okres 1 h – 90 dni, najwyżej 1000 wskazanych wpisów)")
		return
	}
	f := events.QuarantineFilter{From: s.now().Add(-time.Duration(req.Hours) * time.Hour), Source: strings.TrimSpace(req.Source),
		Reason: strings.TrimSpace(req.Reason), Agent: strings.TrimSpace(req.Agent), EventIDs: req.EventIDs}
	if !qm.running.CompareAndSwap(false, true) {
		writeError(w, http.StatusConflict, "busy", "trwa inne zlecenie ponownego przetwarzania – poczekaj na jego koniec")
		return
	}
	started := false
	defer func() {
		if !started {
			qm.running.Store(false)
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	items, err := qm.Source.QuarantineItems(ctx, f, maxReprocessItems+1)
	if err != nil {
		writeError(w, http.StatusBadGateway, "events_failed", err.Error())
		return
	}
	limited := len(items) > maxReprocessItems
	if limited {
		items = items[:maxReprocessItems]
	}
	// Bez wpisów już odzyskanych (wynik w Sadze).
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.EventID
	}
	outcomes, err := qm.Store.QuarantineOutcomes(r.Context(), ids)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	todo := items[:0]
	for _, it := range items {
		if o, ok := outcomes[it.EventID]; !ok || !o.Recovered {
			todo = append(todo, it)
		}
	}
	if len(todo) == 0 {
		writeError(w, http.StatusBadRequest, "nothing_to_do", "brak wpisów do przetworzenia (filtr pusty, źródła nieobsługiwane albo wpisy już odzyskane)")
		return
	}
	job, err := qm.Store.CreateQuarantineJob(r.Context(), a.user.Username, f, len(todo))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "quarantine_reprocess", strconv.FormatInt(job.ID, 10), map[string]any{"items": len(todo), "hours": req.Hours,
		"source": f.Source, "reason": f.Reason, "agent": f.Agent, "event_ids": len(req.EventIDs), "limited": limited})
	started = true
	go func() {
		defer qm.running.Store(false)
		qm.run(job.ID, todo)
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job, "limited": limited})
}

// run wysyła zlecenie częściami (do 500 wpisów i MaxRequestBytes treści);
// część z błędem ponawia trzy razy, potem kończy zlecenie z błędem.
func (q *Quarantine) run(job int64, items []reprocess.Item) {
	ctx := context.Background()
	log := q.Log.With("job", job)
	chunk, size, n := []reprocess.Item{}, 0, 0
	send := func() error {
		if len(chunk) == 0 {
			return nil
		}
		n++
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false) // XML zdarzeń bez zamiany < > & na sekwencje \u – mniejsze żądanie
		if err := enc.Encode(reprocess.Request{Job: job, Chunk: n, Items: chunk}); err != nil {
			return err
		}
		data := buf.Bytes()
		var rep reprocess.Reply
		for attempt := 1; ; attempt++ {
			rctx, cancel := context.WithTimeout(ctx, time.Minute)
			out, err := q.Request(rctx, data)
			cancel()
			if err == nil {
				rep = reprocess.Reply{}
				if err = json.Unmarshal(out, &rep); err == nil && rep.Error != "" {
					err = errors.New(rep.Error)
				}
			}
			if err == nil {
				break
			}
			if attempt == 3 {
				return err
			}
			log.Warn("część zlecenia nieudana – ponowię", "chunk", n, "err", err)
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		failed := map[string]string{}
		for _, f := range rep.Failed {
			failed[f.EventID] = f.Reason
		}
		chunk, size = chunk[:0], 0
		return q.Store.RecordQuarantineOutcomes(ctx, job, rep.Recovered, failed)
	}
	var err error
	for _, it := range items {
		if len(chunk) > 0 && (len(chunk) >= 500 || size+len(it.Raw) > reprocess.MaxRequestBytes) {
			if err = send(); err != nil {
				break
			}
		}
		chunk = append(chunk, it)
		size += len(it.Raw)
	}
	if err == nil {
		err = send()
	}
	msg := ""
	if err != nil {
		msg = err.Error()
		log.Error("zlecenie ponownego przetworzenia kwarantanny nieudane", "err", err)
	} else {
		log.Info("zlecenie ponownego przetworzenia kwarantanny zakończone", "items", len(items))
	}
	if ferr := q.Store.FinishQuarantineJob(ctx, job, msg); ferr != nil {
		log.Error("zapis końca zlecenia nieudany", "err", ferr)
	}
}
