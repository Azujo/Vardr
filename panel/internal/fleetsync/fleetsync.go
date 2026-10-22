// SPDX-License-Identifier: AGPL-3.0-or-later

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
	MarkUninstallTokensUsed(ctx context.Context, uses []store.TokenUse) ([]store.TokenUse, error)
}

// Retire wycofuje agenta odinstalowanego tokenem z panelu: unieważnia jego
// certyfikaty (agent nie wyśle już niczego, nawet jeśli klucz został na
// dysku) – wywoływane raz, przy pierwszym zgłoszeniu deinstalacji.
type Retire func(ctx context.Context, use store.TokenUse) error

// TokenUses: tokeny deinstalacji użyte według raportu agenta (zatrzymanie
// albo deinstalacja tokenem w status.protection.events).
func TokenUses(agentID string, status json.RawMessage) []store.TokenUse {
	var st struct {
		Protection *contract.ProtectionStatus `json:"protection"`
	}
	if json.Unmarshal(status, &st) != nil || st.Protection == nil {
		return nil
	}
	var out []store.TokenUse
	for _, e := range st.Protection.Events {
		if e.TokenID != "" && (e.Kind == contract.TamperStopToken || e.Kind == contract.TamperUninstallTok || e.Kind == contract.TamperUpgrade) {
			out = append(out, store.TokenUse{AgentID: agentID, TokenID: e.TokenID, Action: e.Kind, User: e.User, At: e.At})
		}
	}
	return out
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

// ApplyTokenUses oznacza użyte tokeny deinstalacji, a agenta, który zgłosił
// pierwszy raz deinstalację tokenem wydanym w panelu, wycofuje (retire).
func ApplyTokenUses(ctx context.Context, log *slog.Logger, st Store, retire Retire, uses []store.TokenUse) {
	applied, err := st.MarkUninstallTokensUsed(ctx, uses)
	if err != nil {
		log.Warn("oznaczenie użytych tokenów deinstalacji nieudane", "err", err)
	}
	for _, u := range applied {
		if u.Action != contract.TamperUninstallTok || retire == nil {
			continue
		}
		if err := retire(ctx, u); err != nil {
			log.Error("wycofanie odinstalowanego agenta nieudane – unieważnij certyfikat ręcznie", "agent", u.AgentID, "err", err)
		} else {
			log.Info("agent odinstalowany tokenem – certyfikaty unieważnione", "agent", u.AgentID, "token", u.TokenID)
		}
	}
}

// Run pobiera heartbeaty partiami i zapisuje je do zakończenia ctx.
// Wiadomość jest potwierdzana dopiero po zapisie w bazie.
func Run(ctx context.Context, log *slog.Logger, cons jetstream.Consumer, st Store, retire Retire) {
	for ctx.Err() == nil {
		batch, err := cons.Fetch(500, jetstream.FetchMaxWait(2*time.Second))
		if err != nil {
			log.Warn("pobranie heartbeatów nieudane", "err", err)
			sleep(ctx, 5*time.Second)
			continue
		}
		var msgs []jetstream.Msg
		var agents []store.Agent
		var uses []store.TokenUse
		for msg := range batch.Messages() {
			var hb contract.ServerHeartbeat
			if err := json.Unmarshal(msg.Data(), &hb); err != nil || hb.AgentID == "" {
				log.Warn("nieczytelny heartbeat – pominięty", "subject", msg.Subject(), "err", err)
				_ = msg.Term()
				continue
			}
			msgs = append(msgs, msg)
			agents = append(agents, ToAgent(hb))
			uses = append(uses, TokenUses(hb.AgentID, hb.Status)...)
		}
		if len(agents) == 0 {
			continue
		}
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = st.UpsertAgents(wctx, agents)
		if err == nil {
			ApplyTokenUses(wctx, log, st, retire, uses)
		}
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
