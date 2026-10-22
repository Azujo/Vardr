// SPDX-License-Identifier: AGPL-3.0-or-later

// Package contract opisuje kontrakt paczki agent → serwer (roadmapa, załącznik A).
// Pakiet jest współdzielony przez agenta i serwer, żeby obie strony zawsze
// używały tych samych typów i tych samych reguł walidacji.
package contract

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	// SchemaBatchV1 to identyfikator wersji formatu paczki.
	SchemaBatchV1 = "siem.batch.v1"

	// IngestPath to ścieżka endpointu przyjmującego paczki.
	IngestPath = "/v1/ingest"

	// StatusAccepted oznacza, że serwer trwale zapisał paczkę.
	StatusAccepted = "accepted"

	// MaxEventsPerBatch to górny limit zdarzeń w jednej paczce akceptowany przez serwer.
	MaxEventsPerBatch = 5000
)

// Batch to paczka zdarzeń wysyłana przez agenta.
type Batch struct {
	Schema  string    `json:"schema"`
	BatchID string    `json:"batch_id"`
	AgentID string    `json:"agent_id"`
	SentAt  time.Time `json:"sent_at"`
	Events  []Event   `json:"events"`
}

// Event to pojedyncze surowe zdarzenie. Parsowanie odbywa się na serwerze.
type Event struct {
	ID     string    `json:"id"`
	Source string    `json:"source"`
	ReadAt time.Time `json:"read_at"`
	Raw    string    `json:"raw"`
	// Truncated: raw został przycięty do limitu rozmiaru zdarzenia agenta;
	// OriginalSize to pierwotny rozmiar w bajtach. Pola opcjonalne (v1).
	Truncated    bool `json:"truncated,omitempty"`
	OriginalSize int  `json:"original_size,omitempty"`
	// Peer: adres urządzenia, które przysłało log (kolektor syslog) – pole
	// opcjonalne (v1); dla Event Log puste.
	Peer string `json:"peer,omitempty"`
}

// Response to odpowiedź serwera na paczkę.
// HeaderServerTime: czas serwera (RFC 3339, ns) w odpowiedzi na heartbeat –
// agent wylicza z niego odchylenie swojego zegara.
// Serwer wysyła też dawny nagłówek (LegacyHeaderServerTime) dla agentów
// sprzed zmiany nazwy na Vardr (do 0.7.4).
const (
	HeaderServerTime       = "X-Vardr-Time"
	LegacyHeaderServerTime = "X-Heimdall-Time"
)

type Response struct {
	BatchID string `json:"batch_id"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

// EventID buduje stabilny identyfikator zdarzenia:
// {agent_id}:{kanał}:g{generacja}:{numer rekordu}.
func EventID(agentID, channel string, generation uint32, recordID uint64) string {
	return fmt.Sprintf("%s:%s:g%d:%d", agentID, channel, generation, recordID)
}

// Validate sprawdza strukturę paczki. Tożsamość nadawcy (zgodność agent_id
// z certyfikatem) sprawdza serwer osobno.
func (b *Batch) Validate() error {
	if b.Schema != SchemaBatchV1 {
		return fmt.Errorf("nieobsługiwany schemat %q", b.Schema)
	}
	if b.BatchID == "" {
		return errors.New("brak batch_id")
	}
	if b.AgentID == "" {
		return errors.New("brak agent_id")
	}
	if len(b.Events) == 0 {
		return errors.New("paczka bez zdarzeń")
	}
	if len(b.Events) > MaxEventsPerBatch {
		return fmt.Errorf("za dużo zdarzeń w paczce: %d > %d", len(b.Events), MaxEventsPerBatch)
	}
	prefix := b.AgentID + ":"
	for i, e := range b.Events {
		switch {
		case !strings.HasPrefix(e.ID, prefix):
			return fmt.Errorf("zdarzenie %d: id %q nie należy do agenta %q", i, e.ID, b.AgentID)
		case e.Source == "":
			return fmt.Errorf("zdarzenie %d: brak source", i)
		case e.Raw == "":
			return fmt.Errorf("zdarzenie %d: puste raw", i)
		case e.Peer != "" && !validPeer(e.Peer):
			return fmt.Errorf("zdarzenie %d: peer %.64q to nie adres IP", i, e.Peer)
		}
	}
	return nil
}

// NewBatchID zwraca identyfikator UUIDv7 (uporządkowany w czasie).
func NewBatchID() string {
	var u [16]byte
	ms := uint64(time.Now().UnixMilli())
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ms)
	copy(u[0:6], ts[2:8])
	_, _ = rand.Read(u[6:])
	u[6] = (u[6] & 0x0f) | 0x70 // wersja 7
	u[8] = (u[8] & 0x3f) | 0x80 // wariant RFC 4122
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// validPeer: adres nadawcy syslog to adres IP (trafia do pól zdarzenia
// i zastępuje nazwę hosta, gdy wiadomość jej nie ma).
func validPeer(p string) bool {
	_, err := netip.ParseAddr(p)
	return err == nil && len(p) <= 64
}
