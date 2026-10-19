// Package normalize zamienia surowe zdarzenia od agentów na model.Event
// (podzbiór ECS + pola specyficzne dla źródła w mapie Fields).
package normalize

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"siem/internal/contract"
	"siem/internal/decode"
	"siem/internal/identity"
	"siem/internal/model"
)

// Bity słów kluczowych audytu Windows.
const (
	keywordAuditFailure = 0x10000000000000
	keywordAuditSuccess = 0x20000000000000
)

// MaxFutureSkew: czas zdarzenia późniejszy od czasu przyjęcia o więcej niż
// ta wartość jest oznaczany jako podejrzany (time_quality=future).
const MaxFutureSkew = 5 * time.Minute

// Zakres dat przyjmowanych w kolumnie timestamp. Czas spoza zakresu (np.
// zerowy FILETIME = 1601 r. albo zepsuty zegar) zastępujemy czasem
// przyjęcia i oznaczamy time_quality=invalid – inaczej ClickHouse
// odrzuciłby wiersz albo zapisał bzdurną datę.
var (
	minEventTime = time.Date(1970, 1, 2, 0, 0, 0, 0, time.UTC)
	maxEventTime = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
)

// ErrUnsupportedSource oznacza źródło, dla którego nie ma dekodera.
var ErrUnsupportedSource = errors.New("brak dekodera dla źródła")

// Event normalizuje pojedyncze zdarzenie z paczki agenta.
func Event(ev contract.Event, agentID string, ingested time.Time) (model.Event, error) {
	e, err := event(ev, agentID, ingested)
	if err == nil {
		e.Identity = identity.Current().ResolveOn(e.UserName, e.UserDomain, e.HostName)
	}
	return e, err
}

func event(ev contract.Event, agentID string, ingested time.Time) (model.Event, error) {
	if strings.HasPrefix(ev.Source, "syslog:") || decode.IsAPI(ev.Source) {
		return decode.Event(ev, agentID, ingested, Decoders.Load(), SyslogLocation)
	}
	if !strings.HasPrefix(ev.Source, "wineventlog:") {
		return model.Event{}, fmt.Errorf("%w %q", ErrUnsupportedSource, ev.Source)
	}
	w, err := parseWinEvent(ev.Raw)
	if err != nil {
		if ev.Truncated {
			return model.Event{}, fmt.Errorf("przycięte zdarzenie nie jest poprawnym XML: %w", err)
		}
		return model.Event{}, fmt.Errorf("niepoprawny XML zdarzenia: %w", err)
	}
	code, err := strconv.ParseUint(strings.TrimSpace(w.EventID), 10, 32)
	if err != nil {
		return model.Event{}, fmt.Errorf("brak lub niepoprawny EventID %q", w.EventID)
	}
	channel := w.Channel
	if channel == "" {
		channel = strings.TrimPrefix(ev.Source, "wineventlog:")
	}

	e := model.Event{
		Ingested:  ingested.UTC(),
		ID:        ev.ID,
		AgentID:   agentID,
		Dataset:   Dataset(channel),
		Code:      uint32(code),
		Provider:  w.Provider,
		HostName:  strings.ToLower(w.Computer),
		Raw:       ev.Raw,
		Truncated: ev.Truncated,
		Parser:    model.ParserVersion,
		Fields:    map[string]string{},
	}

	e.Timestamp, e.TimeQuality = eventTime(w.SystemTime, e.Ingested)

	// Pola źródłowe: EventData (Data Name=…) lub UserData (liście elementów).
	var unnamed []string
	for i, d := range w.Data {
		name := d.Name
		if name == "" {
			name = "param" + strconv.Itoa(i+1)
			unnamed = append(unnamed, d.Value)
		}
		e.Fields[name] = d.Value
	}
	for k, v := range w.UserData {
		e.Fields[k] = v
	}
	if len(unnamed) > 0 {
		e.Message = strings.Join(unnamed, " | ")
	}
	setIfNotEmpty(e.Fields, "winlog.channel", channel)
	setIfNotEmpty(e.Fields, "winlog.record_id", w.EventRecordID)
	setIfNotEmpty(e.Fields, "winlog.level", w.Level)
	setIfNotEmpty(e.Fields, "winlog.keywords", w.Keywords)
	setIfNotEmpty(e.Fields, "winlog.user_id", w.UserID)

	e.Outcome = outcomeFromKeywords(w.Keywords)
	applyECS(&e)
	return e, nil
}

// Dataset zamienia nazwę kanału na event.dataset.
func Dataset(channel string) string {
	switch strings.ToLower(channel) {
	case "security":
		return "windows.security"
	case "system":
		return "windows.system"
	case "application":
		return "windows.application"
	case "microsoft-windows-sysmon/operational":
		return "windows.sysmon"
	case "microsoft-windows-powershell/operational":
		return "windows.powershell"
	case "microsoft-windows-windows defender/operational":
		return "windows.defender"
	}
	var b strings.Builder
	b.WriteString("windows.")
	for _, r := range strings.ToLower(channel) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func eventTime(systemTime string, ingested time.Time) (time.Time, string) {
	t, err := time.Parse(time.RFC3339Nano, systemTime)
	if err != nil {
		return ingested, "missing"
	}
	t = t.UTC()
	if t.Before(minEventTime) || !t.Before(maxEventTime) {
		return ingested, "invalid"
	}
	if t.Sub(ingested) > MaxFutureSkew {
		return t, "future"
	}
	return t, ""
}

func outcomeFromKeywords(kw string) string {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(kw), "0x"), 16, 64)
	if err != nil {
		return ""
	}
	switch {
	case v&keywordAuditFailure != 0:
		return "failure"
	case v&keywordAuditSuccess != 0:
		return "success"
	}
	return ""
}

func setIfNotEmpty(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

// clean usuwa wartości-wypełniacze używane przez Windows.
func clean(v string) string {
	v = strings.TrimSpace(v)
	if v == "-" || v == "" {
		return ""
	}
	return v
}

func normalizeIP(v string) string {
	v = clean(v)
	v = strings.TrimPrefix(v, "::ffff:")
	return v
}
