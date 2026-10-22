// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fleet opisuje przepływ heartbeatów agentów przez NATS:
// siem-ingest publikuje, siem-api (panel) odbiera i zapisuje w bazie Saga.
// Współdzielony przez serwer i panel, żeby obie strony miały tę samą
// konfigurację strumienia.
package fleet

import (
	"context"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

const (
	StreamHeartbeats = "SIEM_HEARTBEATS"
	subjectPrefix    = "siem.heartbeat."
	SubjectAll       = subjectPrefix + ">"

	// ConsumerPanel to trwały konsument panelu (kopie siem-api dzielą się wiadomościami).
	ConsumerPanel = "panel-agents"
)

// Subject zwraca temat heartbeatów agenta.
func Subject(agentID string) string { return subjectPrefix + agentID }

// StreamConfig: strumień trzyma tylko ostatni heartbeat każdego agenta
// (MaxMsgsPerSubject=1) – to „aktualny stan floty”. Panel po restarcie od
// razu dostaje stan wszystkich agentów, a utrata starszych heartbeatów nie
// ma znaczenia.
func StreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:              StreamHeartbeats,
		Subjects:          []string{SubjectAll},
		Storage:           jetstream.FileStorage,
		Retention:         jetstream.LimitsPolicy,
		MaxMsgsPerSubject: 1,
		MaxAge:            24 * time.Hour,
		MaxMsgSize:        512 << 10,
		Discard:           jetstream.DiscardOld,
	}
}

// ConsumerConfig to konfiguracja konsumenta panelu.
func ConsumerConfig() jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Durable:       ConsumerPanel,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		MaxAckPending: 4096,
	}
}

// Ensure tworzy lub aktualizuje strumień i konsumenta panelu.
func Ensure(ctx context.Context, js jetstream.JetStream) (jetstream.Consumer, error) {
	if _, err := js.CreateOrUpdateStream(ctx, StreamConfig()); err != nil {
		return nil, err
	}
	return js.CreateOrUpdateConsumer(ctx, StreamHeartbeats, ConsumerConfig())
}
