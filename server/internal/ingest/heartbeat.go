package ingest

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"siem/internal/contract"
	"siem/internal/fleet"
)

// HeartbeatPublisher przekazuje heartbeat dalej (NATS → panel).
type HeartbeatPublisher interface {
	PublishHeartbeat(ctx context.Context, hb contract.ServerHeartbeat) error
}

// HeartbeatHandler obsługuje POST /v1/heartbeat. Heartbeat nie podlega
// kontroli przyjęć paczek – jest mały i rzadki (1/min na agenta), a panel
// powinien widzieć agentów także wtedy, gdy potok jest przeciążony.
type HeartbeatHandler struct {
	Pub     HeartbeatPublisher
	Log     *slog.Logger
	Version string

	Accepted, Rejected atomic.Int64
}

func (h *HeartbeatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(code int, msg string) {
		if code != http.StatusOK {
			h.Rejected.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(contract.HeaderServerTime, time.Now().UTC().Format(time.RFC3339Nano))
		w.WriteHeader(code)
		resp := contract.Response{Error: msg}
		if code == http.StatusOK {
			resp.Status = "ok"
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		reply(http.StatusUnauthorized, "brak certyfikatu klienta")
		return
	}
	cert := r.TLS.PeerCertificates[0]
	agentID := cert.Subject.CommonName
	if !agentIDPattern.MatchString(agentID) {
		reply(http.StatusForbidden, "niepoprawny identyfikator agenta w certyfikacie")
		return
	}

	var body io.Reader = http.MaxBytesReader(w, r.Body, contract.MaxHeartbeatBytes)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(body)
		if err != nil {
			reply(http.StatusBadRequest, "niepoprawny gzip")
			return
		}
		body = io.LimitReader(zr, contract.MaxHeartbeatBytes+1)
	}
	data, err := io.ReadAll(body)
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe) || len(data) > contract.MaxHeartbeatBytes:
		reply(http.StatusRequestEntityTooLarge, "heartbeat za duży")
		return
	case err != nil:
		reply(http.StatusBadRequest, "błąd odczytu")
		return
	}
	var hb contract.Heartbeat
	if err := json.Unmarshal(data, &hb); err != nil {
		reply(http.StatusBadRequest, "niepoprawny JSON")
		return
	}
	if hb.AgentID != agentID {
		h.Log.Warn("niezgodna tożsamość agenta w heartbeacie", "cert_cn", agentID, "agent_id", hb.AgentID, "remote", r.RemoteAddr)
		reply(http.StatusForbidden, "agent_id niezgodny z certyfikatem")
		return
	}
	if err := hb.Validate(); err != nil {
		reply(http.StatusBadRequest, err.Error())
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	shb := contract.ServerHeartbeat{
		Heartbeat: hb, ReceivedAt: time.Now().UTC(), RemoteIP: ip,
		CertNotAfter: cert.NotAfter.UTC(), CertSerial: cert.SerialNumber.Text(16), IngestVersion: h.Version,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.Pub.PublishHeartbeat(ctx, shb); err != nil {
		h.Log.Warn("publikacja heartbeatu nieudana", "agent_id", agentID, "err", err)
		w.Header().Set("Retry-After", "60")
		reply(http.StatusServiceUnavailable, "kolejka chwilowo niedostępna")
		return
	}
	h.Accepted.Add(1)
	reply(http.StatusOK, "")
}

// PublishHeartbeat zapisuje heartbeat w strumieniu SIEM_HEARTBEATS.
func (p *JetStreamPublisher) PublishHeartbeat(ctx context.Context, hb contract.ServerHeartbeat) error {
	data, err := json.Marshal(hb)
	if err != nil {
		return err
	}
	_, err = p.JS.PublishMsg(ctx, &nats.Msg{Subject: fleet.Subject(hb.AgentID), Data: data})
	return err
}

var _ HeartbeatPublisher = (*JetStreamPublisher)(nil)
