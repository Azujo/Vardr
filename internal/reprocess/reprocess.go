// Package reprocess to protokół ponownego przetwarzania kwarantanny (etap
// 6d): panel wysyła wpisy kwarantanny żądaniem NATS (request-reply) do
// normalizatora, który normalizuje je bieżącym kodem i dekoderami,
// publikuje odzyskane zdarzenia w SIEM_EVENTS (zapis i detekcja jak dla
// nowych zdarzeń) i odpowiada wynikiem. Surowe paczki nie wracają do
// SIEM_RAW – archiwum NIS2 ma już oryginały i nie dostaje duplikatów.
package reprocess

import (
	"strings"
	"time"
)

// Subject: temat żądań (kolejka „normalizer” – jeden normalizator na żądanie).
const Subject = "siem.reprocess"

// MaxRequestBytes: najwięcej treści (raw) w jednym żądaniu – zapas do
// max_payload NATS (8 MB) na JSON (cudzysłowy i znaki sterujące w treści
// rosną przy kodowaniu) i nagłówki.
const MaxRequestBytes = 2 << 20

// Item to wpis kwarantanny do ponownego przetworzenia.
type Item struct {
	EventID   string    `json:"event_id"`
	AgentID   string    `json:"agent_id"`
	Source    string    `json:"source"`
	Peer      string    `json:"peer,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
	Raw       string    `json:"raw"`
	Ingested  time.Time `json:"ingested"` // przyjęcie pierwotne (trafienie do kwarantanny)
}

// Request to część zlecenia (Chunk – numer kolejny, do identyfikatora paczki).
type Request struct {
	Job   int64  `json:"job"`
	Chunk int    `json:"chunk"`
	Items []Item `json:"items"`
}

// Failure to wpis, którego nadal nie da się znormalizować.
type Failure struct {
	EventID string `json:"event_id"`
	Reason  string `json:"reason"`
}

// Reply to wynik części zlecenia. Error – błąd całej części (np. publikacja
// w NATS), wtedy Recovered i Failed są puste i część można ponowić.
type Reply struct {
	Recovered []string  `json:"recovered,omitempty"`
	Failed    []Failure `json:"failed,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Supported mówi, czy wpis o tym źródle da się przetworzyć ponownie:
// zdarzenia agentów (Windows, syslog). Odrzucone przez ClickHouse mają jako
// źródło zbiór danych, a wpisy ścieżki odtwarzania – przedrostek replay/.
func Supported(source string) bool {
	return strings.HasPrefix(source, "wineventlog:") || strings.HasPrefix(source, "syslog:")
}
