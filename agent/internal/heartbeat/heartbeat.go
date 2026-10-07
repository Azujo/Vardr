// Package heartbeat co minutę wysyła na serwer stan agenta – ten sam,
// który pokazuje `siem_agent status`. Panel (Huginn) widzi dzięki temu
// listę agentów, ich wersje, ostrzeżenia i to, czy są online.
package heartbeat

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"time"

	"siem/internal/contract"
)

// Sender wysyła heartbeaty.
type Sender struct {
	Client  *http.Client
	URL     string // adres endpointu heartbeatu (patrz URLFromIngest)
	AgentID string
	Version string
	Started time.Time
	// Status zwraca bieżący stan agenta (status.json).
	Status func() any
	Log    *slog.Logger

	Interval   time.Duration // domyślnie contract.HeartbeatInterval
	FirstAfter time.Duration // pierwszy heartbeat po starcie (domyślnie 5 s)

	hostname, os string
}

// URLFromIngest wyznacza adres heartbeatu z adresu endpointu paczek
// (ten sam serwer i port, inna ścieżka).
func URLFromIngest(ingest string) (string, error) {
	u, err := url.Parse(ingest)
	if err != nil {
		return "", err
	}
	u.Path, u.RawQuery = contract.HeartbeatPath, ""
	return u.String(), nil
}

// Run wysyła heartbeaty do zakończenia ctx. Błędy nie zatrzymują agenta –
// heartbeat to informacja dla panelu, nie część dostarczania zdarzeń.
func (s *Sender) Run(ctx context.Context) {
	if s.Interval <= 0 {
		s.Interval = contract.HeartbeatInterval
	}
	if s.FirstAfter <= 0 {
		s.FirstAfter = 5 * time.Second
	}
	s.hostname, _ = os.Hostname()
	s.os = osVersion()

	wait := s.FirstAfter
	failing := false
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		err := s.send(ctx)
		switch {
		case err != nil && !failing:
			s.Log.Warn("heartbeat nieudany – panel może pokazywać agenta jako offline", "err", err)
			failing = true
		case err == nil && failing:
			s.Log.Info("heartbeat ponownie działa")
			failing = false
		}
		// Rozrzut ±10%, żeby tysiące agentów nie wysyłały w tej samej sekundzie.
		wait = s.Interval - s.Interval/10 + time.Duration(rand.Int64N(int64(s.Interval/5)+1))
	}
}

func (s *Sender) send(ctx context.Context) error {
	st, err := json.Marshal(s.Status())
	if err != nil {
		return err
	}
	hb := contract.Heartbeat{
		Schema: contract.SchemaHeartbeatV1, AgentID: s.AgentID, SentAt: time.Now().UTC(),
		Version: s.Version, Hostname: s.hostname, OS: s.os, StartedAt: s.Started.UTC(), Status: st,
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(hb); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, s.URL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("serwer nie obsługuje heartbeatu (starsza wersja siem-ingest)")
	default:
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
}
