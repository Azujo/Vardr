// Package fleetsync odbiera heartbeaty agentów ze strumienia NATS
// (publikowane przez siem-ingest) i zapisuje stan agentów w bazie Saga.
package fleetsync

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/contract"
	"siem/panel/internal/api/store"
)

// Store to zapis stanu agentów.
type Store interface {
	UpsertAgents(ctx context.Context, agents []store.Agent) error
}

// ToAgent zamienia heartbeat na wiersz tabeli agents.
func ToAgent(hb contract.ServerHeartbeat) store.Agent {
	a := store.Agent{
		ID: hb.AgentID, Hostname: hb.Hostname, OS: hb.OS, Version: hb.Version, RemoteIP: hb.RemoteIP,
		LastSeen: hb.ReceivedAt, CertSerial: hb.CertSerial, Status: hb.Status,
	}
	if !hb.StartedAt.IsZero() {
		t := hb.StartedAt
		a.StartedAt = &t
	}
	if !hb.CertNotAfter.IsZero() {
		t := hb.CertNotAfter
		a.CertNotAfter = &t
	}
	return a
}

// Run pobiera heartbeaty partiami i zapisuje je do zakończenia ctx.
// Wiadomość jest potwierdzana dopiero po zapisie w bazie.
func Run(ctx context.Context, log *slog.Logger, cons jetstream.Consumer, st Store) {
	for ctx.Err() == nil {
		batch, err := cons.Fetch(500, jetstream.FetchMaxWait(2*time.Second))
		if err != nil {
			log.Warn("pobranie heartbeatów nieudane", "err", err)
			sleep(ctx, 5*time.Second)
			continue
		}
		var msgs []jetstream.Msg
		var agents []store.Agent
		for msg := range batch.Messages() {
			var hb contract.ServerHeartbeat
			if err := json.Unmarshal(msg.Data(), &hb); err != nil || hb.AgentID == "" {
				log.Warn("nieczytelny heartbeat – pominięty", "subject", msg.Subject(), "err", err)
				_ = msg.Term()
				continue
			}
			msgs = append(msgs, msg)
			agents = append(agents, ToAgent(hb))
		}
		if len(agents) == 0 {
			continue
		}
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = st.UpsertAgents(wctx, agents)
		cancel()
		if err != nil {
			log.Error("zapis stanu agentów nieudany – ponowię", "agents", len(agents), "err", err)
			for _, m := range msgs {
				_ = m.NakWithDelay(10 * time.Second)
			}
			continue
		}
		for _, m := range msgs {
			_ = m.Ack()
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
