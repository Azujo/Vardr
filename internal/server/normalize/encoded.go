package normalize

import (
	"encoding/json"
	"errors"
	"time"

	"siem/internal/contract"
	"siem/internal/server/bus"
	"siem/internal/server/model"
)

// ErrUnreadable oznacza paczkę, której nie da się odczytać (uszkodzony gzip
// lub JSON) – ponowne przetwarzanie nic nie zmieni.
var ErrUnreadable = errors.New("nieczytelna wiadomość")

// Encoded to pełna ścieżka normalizatora dla jednej wiadomości: rozpakowanie
// paczki agenta, normalizacja i spakowanie wyniku (model.Batch, gzip+JSON).
// Wydzielona z programu, żeby dało się ją mierzyć bez NATS.
func Encoded(gz []byte, agentID string, receivedAt time.Time, maxDecompressed int64) ([]byte, model.Batch, error) {
	data, err := bus.Gunzip(gz, maxDecompressed)
	if err != nil {
		return nil, model.Batch{}, errors.Join(ErrUnreadable, err)
	}
	var b contract.Batch
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, model.Batch{}, errors.Join(ErrUnreadable, err)
	}
	nb := Batch(b, agentID, receivedAt)
	out, err := json.Marshal(nb)
	if err != nil {
		return nil, nb, errors.Join(ErrUnreadable, err)
	}
	packed, err := bus.Gzip(out)
	return packed, nb, err
}
