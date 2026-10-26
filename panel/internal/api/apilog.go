// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"time"

	"siem/panel/internal/api/store"
)

// Historia zapytań tokenów API: każde zapytanie programu (metoda, ścieżka
// z parametrami, wynik, czas) trafia do logu siem-api i – paczkami w tle –
// do bazy (api_token_requests), skąd panel pokazuje ją przy tokenie.
// Zapis w tle nie spowalnia odpowiedzi; przy zapchanej bazie wpisy ponad
// bufor są pomijane (licznik w logu), a API działa dalej.

const (
	tokenLogBuffer      = 4096
	tokenLogBatch       = 500
	tokenLogFlush       = time.Second
	defaultTokenLogDays = 30
	maxLoggedPath       = 500
)

// statusWriter zapamiętuje kod odpowiedzi (do historii zapytań).
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap: http.ResponseController (np. Flush przy pobieraniu eksportu).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) tokenLogDays() int {
	if s.TokenLogDays > 0 {
		return s.TokenLogDays
	}
	return defaultTokenLogDays
}

// logTokenRequest zapisuje zapytanie tokenu w logu i kolejce do bazy.
func (s *Server) logTokenRequest(r *http.Request, t *store.APIToken, status int, took time.Duration, ip string) {
	if status == 0 {
		status = http.StatusOK
	}
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	if len(path) > maxLoggedPath {
		path = path[:maxLoggedPath] + "…"
	}
	s.Log.Info("API token request", "token", t.Name, "token_id", t.ID, "method", r.Method, "path", path,
		"status", status, "ms", took.Milliseconds(), "ip", ip)
	if s.tokenLog == nil {
		return
	}
	select {
	case s.tokenLog <- store.APIRequest{TokenID: t.ID, At: s.now(), Method: r.Method, Path: path, Status: status,
		DurationMS: int(took.Milliseconds()), IP: ip}:
	default:
		s.tokenLogDropped.Add(1)
	}
}

// RunTokenLog zapisuje kolejkę historii zapytań do bazy, aż ctx się
// skończy (wtedy zapisuje resztę). Uruchamiane przez siem-api.
func (s *Server) RunTokenLog(ctx context.Context) {
	if s.tokenLog == nil {
		return
	}
	t := time.NewTicker(tokenLogFlush)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.flushTokenLog(ctx)
		case <-ctx.Done():
			s.flushTokenLog(context.WithoutCancel(ctx))
			return
		}
	}
}

// flushTokenLog zapisuje wszystko, co czeka w kolejce (paczkami).
func (s *Server) flushTokenLog(ctx context.Context) {
	if n := s.tokenLogDropped.Swap(0); n > 0 {
		s.Log.Warn("API token request history: entries dropped (queue full)", "count", n)
	}
	for {
		batch := make([]store.APIRequest, 0, tokenLogBatch)
	fill:
		for len(batch) < tokenLogBatch {
			select {
			case e := <-s.tokenLog:
				batch = append(batch, e)
			default:
				break fill
			}
		}
		if len(batch) == 0 {
			return
		}
		if err := s.APITokens.RecordAPIRequests(ctx, batch); err != nil {
			s.Log.Warn("recording API token requests failed", "count", len(batch), "err", err)
			return
		}
		if len(batch) < tokenLogBatch {
			return
		}
	}
}
