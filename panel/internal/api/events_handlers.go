// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"siem/panel/internal/events"
)

// EventSearcher to wyszukiwarka zdarzeń (Mímir, implementuje events.Searcher).
type EventSearcher interface {
	Search(ctx context.Context, p events.Parsed, from, to time.Time, before *events.Cursor, limit int) ([]events.Event, error)
	Histogram(ctx context.Context, p events.Parsed, from, to time.Time) ([]events.Bucket, time.Duration, uint64, error)
	Get(ctx context.Context, id string, ts time.Time, replay bool) (events.Detail, error)
}

const (
	maxSearchRange = 31 * 24 * time.Hour
	// SearchTimeout: limit czasu zapytania. Sterownik ClickHouse przekazuje go
	// bazie jako max_execution_time = limit + 5 s, a konto siem_panel pozwala
	// najwyżej na 30 s – dlatego 20 s (w bazie 25 s).
	SearchTimeout = 20 * time.Second
)

// searchParams odczytuje zapytanie i zakres czasu (domyślnie ostatnia godzina).
func (s *Server) searchParams(w http.ResponseWriter, r *http.Request) (events.Parsed, time.Time, time.Time, bool) {
	q := r.URL.Query()
	now := s.now()
	to, from := now, now.Add(-time.Hour)
	var err error
	if v := q.Get("to"); v != "" {
		if to, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusBadRequest, "bad_time", "niepoprawny parametr to (RFC 3339)")
			return events.Parsed{}, from, to, false
		}
	}
	if v := q.Get("from"); v != "" {
		if from, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusBadRequest, "bad_time", "niepoprawny parametr from (RFC 3339)")
			return events.Parsed{}, from, to, false
		}
	}
	switch {
	case !from.Before(to):
		writeError(w, http.StatusBadRequest, "bad_range", "początek zakresu musi być przed końcem")
		return events.Parsed{}, from, to, false
	case to.Sub(from) > maxSearchRange:
		writeError(w, http.StatusBadRequest, "bad_range", "zakres wyszukiwania może mieć najwyżej 31 dni")
		return events.Parsed{}, from, to, false
	}
	if len(q.Get("q")) > 2000 {
		writeError(w, http.StatusBadRequest, "bad_query", "zapytanie jest za długie")
		return events.Parsed{}, from, to, false
	}
	p, err := events.Parse(q.Get("q"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_query", err.Error())
		return events.Parsed{}, from, to, false
	}
	// source=replay: zdarzenia odtworzone z archiwum (osobna tabela).
	p.Replay = q.Get("source") == "replay"
	return p, from, to, true
}

func (s *Server) eventsEnabled(w http.ResponseWriter) bool {
	if s.Events == nil {
		writeError(w, http.StatusServiceUnavailable, "events_disabled", "wyszukiwarka zdarzeń wyłączona – brak połączenia z ClickHouse (SIEM_CLICKHOUSE_*)")
		return false
	}
	return true
}

type nextCursor struct {
	Timestamp time.Time `json:"before_ts"`
	ID        string    `json:"before_id"`
}

func (s *Server) searchEvents(w http.ResponseWriter, r *http.Request) {
	if !s.eventsEnabled(w) {
		return
	}
	p, from, to, ok := s.searchParams(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	var before *events.Cursor
	if ts := r.URL.Query().Get("before_ts"); ts != "" {
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_cursor", "niepoprawny kursor stronicowania")
			return
		}
		before = &events.Cursor{Timestamp: t, ID: r.URL.Query().Get("before_id")}
	}
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	start := time.Now()
	list, err := s.Events.Search(ctx, p, from, to, before, limit)
	if err != nil {
		s.searchError(w, r, err)
		return
	}
	resp := map[string]any{"events": list, "took_ms": time.Since(start).Milliseconds(), "from": from, "to": to}
	if len(list) == limit {
		last := list[len(list)-1]
		resp["next"] = nextCursor{Timestamp: last.Timestamp, ID: last.ID}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) eventsHistogram(w http.ResponseWriter, r *http.Request) {
	if !s.eventsEnabled(w) {
		return
	}
	p, from, to, ok := s.searchParams(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	buckets, step, total, err := s.Events.Histogram(ctx, p, from, to)
	if err != nil {
		s.searchError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"buckets": buckets, "interval_s": int(step.Seconds()), "total": total})
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	if !s.eventsEnabled(w) {
		return
	}
	id := r.PathValue("id")
	ts, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("ts"))
	if err != nil || len(id) == 0 || len(id) > 256 {
		writeError(w, http.StatusBadRequest, "bad_request", "podaj identyfikator zdarzenia i czas (ts)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	d, err := s.Events.Get(ctx, id, ts, r.URL.Query().Get("source") == "replay")
	if errors.Is(err, events.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego zdarzenia (mogło zostać usunięte przez retencję)")
		return
	}
	if err != nil {
		s.searchError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"event": d})
}

func (s *Server) eventFields(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"fields": events.FieldHelp()})
}

func (s *Server) searchError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		writeError(w, http.StatusGatewayTimeout, "timeout", "zapytanie trwało zbyt długo – zawęź zakres czasu albo dodaj filtry")
		return
	}
	s.internalError(w, r, err)
}
