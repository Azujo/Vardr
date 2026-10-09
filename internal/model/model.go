// Package model opisuje dane przekazywane między etapami serwera:
// znormalizowane zdarzenia (podzbiór ECS) i wpisy kwarantanny.
package model

import "time"

// ParserVersion trafia do każdego zdarzenia (siem.parser_version).
const ParserVersion = "winevt-1"

// Event to znormalizowane zdarzenie – jeden wiersz tabeli siem.events.
type Event struct {
	Timestamp   time.Time         `json:"timestamp"` // czas wystąpienia (UTC)
	Ingested    time.Time         `json:"ingested"`  // czas przyjęcia przez serwer
	ID          string            `json:"event_id"`
	AgentID     string            `json:"agent_id"`
	Dataset     string            `json:"event_dataset"` // np. windows.security
	Code        uint32            `json:"event_code"`    // Event ID Windows
	Provider    string            `json:"event_provider"`
	Action      string            `json:"event_action"`
	Outcome     string            `json:"event_outcome"` // success | failure | ""
	HostName    string            `json:"host_name"`
	UserName    string            `json:"user_name"`
	UserDomain  string            `json:"user_domain"`
	SourceIP    string            `json:"source_ip"`
	ProcessName string            `json:"process_name"`
	CommandLine string            `json:"process_command_line"`
	Message     string            `json:"message"`
	Fields      map[string]string `json:"fields"`
	Raw         string            `json:"raw"`
	Truncated   bool              `json:"truncated"`
	Parser      string            `json:"parser_version"`
	TimeQuality string            `json:"time_quality"` // "" | "missing" | "future" | "invalid"
	// ReplayID: numer zlecenia odtworzenia z archiwum (tylko ścieżka replay).
	ReplayID uint32 `json:"replay_id,omitempty"`
}

// Quarantined to zdarzenie, którego nie udało się znormalizować.
// Nic nie znika bez śladu – oryginał i powód trafiają do siem.quarantine.
type Quarantined struct {
	Ingested time.Time `json:"ingested"`
	AgentID  string    `json:"agent_id"`
	EventID  string    `json:"event_id"`
	Source   string    `json:"source"`
	Reason   string    `json:"reason"`
	Raw      string    `json:"raw"`
	// Peer: adres nadawcy syslog, Truncated: treść przycięta przez agenta –
	// potrzebne do ponownego przetworzenia z kwarantanny.
	Peer      string `json:"peer,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Batch to wynik normalizacji jednej paczki agenta (jedna wiadomość
// w strumieniu SIEM_EVENTS).
type Batch struct {
	BatchID    string        `json:"batch_id"`
	AgentID    string        `json:"agent_id"`
	Events     []Event       `json:"events"`
	Quarantine []Quarantined `json:"quarantine,omitempty"`
}
