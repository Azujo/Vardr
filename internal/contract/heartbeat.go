package contract

import (
	"encoding/json"
	"errors"
	"time"
)

const (
	// SchemaHeartbeatV1 to identyfikator wersji formatu heartbeatu.
	SchemaHeartbeatV1 = "siem.heartbeat.v1"

	// HeartbeatPath to ścieżka endpointu przyjmującego heartbeat agenta.
	HeartbeatPath = "/v1/heartbeat"

	// HeartbeatInterval to odstęp między heartbeatami. Panel uznaje agenta
	// za offline po 3 interwałach ciszy.
	HeartbeatInterval = time.Minute

	// MaxHeartbeatBytes ogranicza rozmiar heartbeatu (po rozpakowaniu).
	MaxHeartbeatBytes = 256 << 10
)

// Heartbeat to okresowy raport agenta o jego stanie (roadmapa, załącznik C).
// Status to ten sam dokument, który zapisuje `siem_agent status`
// (status.json) – serwer przechowuje go bez interpretacji, panel go wyświetla.
type Heartbeat struct {
	Schema    string          `json:"schema"`
	AgentID   string          `json:"agent_id"`
	SentAt    time.Time       `json:"sent_at"`
	Version   string          `json:"version"`
	Hostname  string          `json:"hostname"`
	OS        string          `json:"os"`
	StartedAt time.Time       `json:"started_at"`
	Status    json.RawMessage `json:"status"`
}

// Validate sprawdza heartbeat. Tożsamość (agent_id z certyfikatu) sprawdza serwer.
func (h *Heartbeat) Validate() error {
	switch {
	case h.Schema != SchemaHeartbeatV1:
		return errors.New("nieobsługiwany schemat heartbeatu")
	case h.AgentID == "":
		return errors.New("brak agent_id")
	case len(h.Hostname) > 255 || len(h.Version) > 64 || len(h.OS) > 255:
		return errors.New("za długie pole tekstowe")
	case len(h.Status) == 0 || !json.Valid(h.Status) || h.Status[0] != '{':
		return errors.New("status musi być obiektem JSON")
	}
	return nil
}

// ServerHeartbeat to heartbeat uzupełniony przez serwer przyjmujący
// (wiadomość w strumieniu SIEM_HEARTBEATS).
type ServerHeartbeat struct {
	Heartbeat
	ReceivedAt    time.Time `json:"received_at"`
	RemoteIP      string    `json:"remote_ip"`
	CertNotAfter  time.Time `json:"cert_not_after"`
	CertSerial    string    `json:"cert_serial"`
	IngestVersion string    `json:"ingest_version,omitempty"`
}
