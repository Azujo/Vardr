// SPDX-License-Identifier: AGPL-3.0-or-later

package heartbeat

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"siem/internal/contract"
)

func TestURLFromIngest(t *testing.T) {
	got, err := URLFromIngest("https://10.0.0.5:8443/v1/ingest?x=1")
	if err != nil || got != "https://10.0.0.5:8443/v1/heartbeat" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestSenderSendsStatus(t *testing.T) {
	var n atomic.Int32
	got := make(chan contract.Heartbeat, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil || r.URL.Path != contract.HeartbeatPath {
			t.Errorf("żądanie: %v %s", err, r.URL.Path)
			return
		}
		var hb contract.Heartbeat
		if err := json.NewDecoder(zr).Decode(&hb); err != nil {
			t.Error(err)
		}
		if n.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // pierwszy nieudany – agent próbuje dalej
			return
		}
		got <- hb
	}))
	defer srv.Close()

	s := &Sender{Client: srv.Client(), URL: srv.URL + contract.HeartbeatPath, AgentID: "agt-1", Version: "0.4.0",
		Started: time.Now(), Status: func() any { return map[string]any{"counters": map[string]int{"accepted": 7}} },
		Log: slog.New(slog.DiscardHandler), Interval: 30 * time.Millisecond, FirstAfter: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	select {
	case hb := <-got:
		if err := hb.Validate(); err != nil || hb.AgentID != "agt-1" || hb.Hostname == "" || hb.OS == "" ||
			string(hb.Status) != `{"counters":{"accepted":7}}` {
			t.Fatalf("%+v %v", hb, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("brak heartbeatu po nieudanej próbie")
	}
}
