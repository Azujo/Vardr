// SPDX-License-Identifier: AGPL-3.0-or-later

package normalize

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"siem/internal/contract"
	"siem/internal/model"
	"siem/server/internal/bus"
)

// ErrUnreadable oznacza paczkę, której nie da się odczytać (uszkodzony gzip
// lub JSON) – ponowne przetwarzanie nic nie zmieni.
var ErrUnreadable = errors.New("unreadable message")

// Encoded to pełna ścieżka normalizatora dla jednej wiadomości: rozpakowanie
// paczki agenta, normalizacja i spakowanie wyniku (model.Batch, gzip+JSON).
// Wydzielona z programu, żeby dało się ją mierzyć bez NATS.
//
// replayID ≠ 0 oznacza paczkę odtworzoną z archiwum: zdarzenia dostają
// numer zlecenia, a wpisy kwarantanny źródło z przedrostkiem „replay/”.
func Encoded(gz []byte, agentID string, receivedAt time.Time, replayID uint32, maxDecompressed int64) ([]byte, model.Batch, error) {
	data, err := bus.Gunzip(gz, maxDecompressed)
	if err != nil {
		return nil, model.Batch{}, errors.Join(ErrUnreadable, err)
	}
	var b contract.Batch
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, model.Batch{}, errors.Join(ErrUnreadable, err)
	}
	nb := Batch(b, agentID, receivedAt)
	if replayID != 0 {
		for i := range nb.Events {
			nb.Events[i].ReplayID = replayID
		}
		for i := range nb.Quarantine {
			nb.Quarantine[i].Source = "replay/" + nb.Quarantine[i].Source
		}
	}
	var out bytes.Buffer
	out.Grow(len(data) + len(data)/2)
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false) // XML bez 003c – krótsza i szybsza serializacja
	if err := enc.Encode(nb); err != nil {
		return nil, nb, errors.Join(ErrUnreadable, err)
	}
	packed, err := bus.Gzip(out.Bytes())
	return packed, nb, err
}
