// SPDX-License-Identifier: AGPL-3.0-or-later

package fleet

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/nats-io/nats.go/jetstream"
)

// RevokedBucket to magazyn klucz-wartość NATS z unieważnionymi certyfikatami
// agentów (klucz = numer seryjny szesnastkowo, wartość = powód). Panel
// zapisuje, siem-ingest obserwuje i odrzuca takie certyfikaty przy
// nawiązywaniu połączenia – ingest nie potrzebuje do tego bazy.
const RevokedBucket = "SIEM_REVOKED_CERTS"

// EnsureRevoked tworzy (lub otwiera) magazyn unieważnień.
func EnsureRevoked(ctx context.Context, js jetstream.JetStream) (jetstream.KeyValue, error) {
	return js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:      RevokedBucket,
		Description: "Revoked Vardr agent certificates",
		History:     1,
		Storage:     jetstream.FileStorage,
	})
}

// RevokedSet to bieżący zbiór unieważnionych numerów seryjnych.
type RevokedSet struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewRevokedSet tworzy pusty zbiór.
func NewRevokedSet() *RevokedSet { return &RevokedSet{m: map[string]string{}} }

// Has sprawdza numer seryjny (szesnastkowo, małe litery).
func (r *RevokedSet) Has(serial string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.m[serial]
	return ok
}

// Len zwraca liczbę unieważnionych certyfikatów.
func (r *RevokedSet) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.m)
}

func (r *RevokedSet) set(serial, reason string, present bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if present {
		r.m[serial] = reason
	} else {
		delete(r.m, serial)
	}
}

// Watch aktualizuje zbiór na bieżąco do zakończenia ctx.
func (r *RevokedSet) Watch(ctx context.Context, kv jetstream.KeyValue, log *slog.Logger) error {
	w, err := kv.WatchAll(ctx)
	if err != nil {
		return err
	}
	defer w.Stop()
	initial := true
	for {
		select {
		case <-ctx.Done():
			return nil
		case e, ok := <-w.Updates():
			if !ok {
				return errors.New("watching revocations ended")
			}
			if e == nil { // koniec stanu początkowego
				if initial {
					log.Info("revoked certificate list loaded", "count", r.Len())
					initial = false
				}
				continue
			}
			present := e.Operation() == jetstream.KeyValuePut
			r.set(e.Key(), string(e.Value()), present)
			if !initial && present {
				log.Warn("agent certificate revoked – connections with it will be rejected", "serial", e.Key(), "reason", string(e.Value()))
			}
		}
	}
}
