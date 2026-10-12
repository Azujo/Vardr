package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"siem/internal/contract"
)

type fakeHBPub struct {
	got []contract.ServerHeartbeat
	err error
}

func (f *fakeHBPub) PublishHeartbeat(_ context.Context, hb contract.ServerHeartbeat) error {
	if f.err != nil {
		return f.err
	}
	f.got = append(f.got, hb)
	return nil
}

func hbRequest(t *testing.T, cn string, hb contract.Heartbeat, gz bool) *http.Request {
	t.Helper()
	body, _ := json.Marshal(hb)
	if gz {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(body)
		zw.Close()
		body = buf.Bytes()
	}
	r := httptest.NewRequest(http.MethodPost, contract.HeartbeatPath, bytes.NewReader(body))
	r.RemoteAddr = "192.168.88.10:51000"
	if gz {
		r.Header.Set("Content-Encoding", "gzip")
	}
	if cn != "" {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{CommonName: cn}, SerialNumber: big.NewInt(0xabc),
			NotAfter: time.Date(2027, 1, 5, 0, 0, 0, 0, time.UTC),
		}}}
	}
	return r
}

func heartbeat(agent string) contract.Heartbeat {
	return contract.Heartbeat{Schema: contract.SchemaHeartbeatV1, AgentID: agent, SentAt: time.Now(), Version: "0.4.0",
		Hostname: "PC01", OS: "Windows 11", Status: json.RawMessage(`{"counters":{"accepted":5}}`)}
}

func TestHeartbeatAcceptedWithServerFields(t *testing.T) {
	p := &fakeHBPub{}
	h := &HeartbeatHandler{Pub: p, Log: slog.New(slog.DiscardHandler), Version: "test"}
	for _, gz := range []bool{false, true} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, hbRequest(t, "agt-1", heartbeat("agt-1"), gz))
		if w.Code != 200 {
			t.Fatalf("gzip=%v: %d %s", gz, w.Code, w.Body.String())
		}
	}
	got := p.got[0]
	if got.RemoteIP != "192.168.88.10" || got.CertSerial != "abc" || got.CertNotAfter.Year() != 2027 ||
		got.Hostname != "PC01" || got.IngestVersion != "test" || got.ReceivedAt.IsZero() {
		t.Fatalf("%+v", got)
	}
}

func TestHeartbeatRejections(t *testing.T) {
	h := &HeartbeatHandler{Pub: &fakeHBPub{}, Log: slog.New(slog.DiscardHandler)}
	bad := heartbeat("agt-1")
	bad.Status = json.RawMessage(`[1,2]`)
	for name, c := range map[string]struct {
		r    *http.Request
		code int
	}{
		"bez certyfikatu":   {hbRequest(t, "", heartbeat("agt-1"), false), 401},
		"podszycie":         {hbRequest(t, "agt-2", heartbeat("agt-1"), false), 403},
		"status nie obiekt": {hbRequest(t, "agt-1", bad, false), 400},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, c.r)
		if w.Code != c.code {
			t.Errorf("%s: %d, chcę %d", name, w.Code, c.code)
		}
	}
	h.Pub = &fakeHBPub{err: errors.New("nats down")}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, hbRequest(t, "agt-1", heartbeat("agt-1"), false))
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("kolejka niedostępna: %d", w.Code)
	}
}

func TestHeartbeatInFlightLimit(t *testing.T) {
	p := &fakeHBPub{}
	h := &HeartbeatHandler{Pub: p, Log: slog.New(slog.DiscardHandler), MaxInFlight: 1}
	h.inFlight.Store(1) // jeden heartbeat właśnie w obsłudze
	w := httptest.NewRecorder()
	h.ServeHTTP(w, hbRequest(t, "agt-1", heartbeat("agt-1"), true))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || h.Throttled.Load() != 1 || len(p.got) != 0 {
		t.Fatalf("limit: %d %v", w.Code, w.Header())
	}
	h.inFlight.Store(0)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, hbRequest(t, "agt-1", heartbeat("agt-1"), true))
	if w.Code != 200 || h.inFlight.Load() != 0 {
		t.Fatalf("po zwolnieniu: %d, w obsłudze %d", w.Code, h.inFlight.Load())
	}
}
