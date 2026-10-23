// SPDX-License-Identifier: AGPL-3.0-or-later

package decode

import (
	"embed"
	"io/fs"
	"net/netip"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // strefy czasowe dekoderów (obrazy usług bez tzdata)

	"siem/internal/contract"
	"siem/internal/lang"
	"siem/internal/model"
)

//go:embed builtin/*.yml
var builtinFS embed.FS

// Builtin zwraca dekodery wbudowane (internal/decode/builtin).
func Builtin(loc *time.Location) ([]*Decoder, error) {
	sub, err := fs.Sub(builtinFS, "builtin")
	if err != nil {
		return nil, err
	}
	return LoadFS(sub, loc)
}

// ParserVersion trafia do zdarzeń z syslog (siem.parser_version);
// APIParserVersion – do zdarzeń z konektorów API (Entra ID).
const (
	ParserVersion    = "syslog-1"
	APIParserVersion = "api-1"
)

// IsAPI: źródło z konektora API (bez nagłówka syslog, treść to rekord JSON).
func IsAPI(source string) bool { return strings.HasPrefix(source, "entra:") }

// Granice czasu jak w normalizatorze zdarzeń Windows.
var (
	minTime = time.Date(1970, 1, 2, 0, 0, 0, 0, time.UTC)
	maxTime = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
)

// MaxFutureSkew: czas zdarzenia późniejszy od przyjęcia o więcej – „future”.
const MaxFutureSkew = 5 * time.Minute

// Event zamienia wiadomość syslog z paczki kolektora na zdarzenie: nagłówek,
// pierwszy pasujący dekoder (bez dekodera – zdarzenie „syslog.generic”
// z treścią). Błąd: treść nie pasuje do parsera dekodera (kwarantanna).
func Event(ev contract.Event, agentID string, ingested time.Time, set *Set, loc *time.Location) (model.Event, error) {
	peer, _ := netip.ParseAddr(ev.Peer)
	e := model.Event{
		Ingested:  ingested.UTC(),
		ID:        ev.ID,
		AgentID:   agentID,
		Raw:       ev.Raw,
		Truncated: ev.Truncated,
		Parser:    ParserVersion,
	}
	var h Header
	if IsAPI(ev.Source) {
		// Rekord z API: bez nagłówka; dekoder wybierany po źródle (match.app).
		h = Header{Facility: -1, Severity: -1, Format: "api", App: ev.Source, Message: ev.Raw}
		e.Parser, e.Provider = APIParserVersion, ev.Source
		e.Fields = map[string]string{"event.source": ev.Source}
	} else {
		h = ParseHeader(ev.Raw, loc, ingested)
		e.Message, e.Provider = h.Message, h.App
		e.Fields = map[string]string{"syslog.peer": ev.Peer, "syslog.format": h.Format}
		if h.App != "" {
			e.Fields["syslog.app"] = h.App
		}
		if h.PID != "" {
			e.Fields["syslog.pid"] = h.PID
		}
		if h.Severity >= 0 {
			e.Fields["syslog.facility"] = strconv.Itoa(h.Facility)
			e.Fields["syslog.severity"] = SeverityName(h.Severity)
		}
		e.HostName = strings.ToLower(h.Host)
		if e.HostName == "" {
			e.HostName = ev.Peer
		}
	}

	var evTime time.Time
	d := set.Find(h, peer)
	if d == nil && IsAPI(ev.Source) {
		return model.Event{}, lang.Errorf("brak dekodera dla źródła %s", "no decoder for source %s", ev.Source)
	}
	if d == nil {
		e.Dataset = "syslog.generic"
	} else {
		res, err := d.Decode(h)
		if err != nil {
			return model.Event{}, err
		}
		e.Dataset = d.Dataset
		for k, v := range res.Fields {
			if _, taken := e.Fields[k]; !taken && !reserved(k) {
				e.Fields[k] = v
			}
		}
		e.Fields["decoder.id"] = d.ID
		e.Fields["decoder.version"] = strconv.Itoa(d.Version)
		apply(&e, res.Targets)
		evTime = res.Time
	}
	if evTime.IsZero() {
		evTime = h.Time
	}
	e.Timestamp, e.TimeQuality = quality(evTime, e.Ingested)
	return e, nil
}

// apply przepisuje pola docelowe dekodera do kolumn zdarzenia.
func apply(e *model.Event, t map[string]string) {
	for k, v := range t {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch k {
		case "host.name":
			e.HostName = strings.ToLower(v)
		case "user.name":
			if dom, user, ok := strings.Cut(v, `\`); ok {
				e.UserDomain, e.UserName = dom, user
			} else {
				e.UserName = v
			}
		case "user.domain":
			e.UserDomain = v
		case "source.ip":
			if a, err := netip.ParseAddr(strings.TrimPrefix(v, "::ffff:")); err == nil {
				e.SourceIP = a.Unmap().String()
			}
		case "process.name":
			e.ProcessName = v
		case "process.command_line":
			e.CommandLine = v
		case "message":
			e.Message = v
		case "event.action":
			e.Action = v
		case "event.outcome":
			e.Outcome = strings.ToLower(v)
		case "event.provider":
			e.Provider = v
		case "event.code":
			if n, err := strconv.ParseUint(strings.TrimLeft(v, "0"), 10, 32); err == nil {
				e.Code = uint32(n)
			}
		default:
			if !reserved(k) {
				e.Fields[k] = v
			}
		}
	}
}

// reserved: pola ustawiane przez Vardra (nagłówek syslog, dekoder,
// ponowne przetworzenie) – treść wiadomości ani definicja dekodera ich nie
// nadpisze.
func reserved(k string) bool {
	return strings.HasPrefix(k, "syslog.") || strings.HasPrefix(k, "decoder.") || strings.HasPrefix(k, "siem.") || k == "event.source"
}

func quality(t, ingested time.Time) (time.Time, string) {
	if t.IsZero() {
		return ingested, "missing"
	}
	t = t.UTC()
	if t.Before(minTime) || !t.Before(maxTime) {
		return ingested, "invalid"
	}
	if t.Sub(ingested) > MaxFutureSkew {
		return t, "future"
	}
	return t, ""
}

// BuiltinSources zwraca definicje YAML dekoderów wbudowanych (id → treść)
// – panel pokazuje je jako punkt wyjścia do własnej wersji.
func BuiltinSources() map[string]string {
	out := map[string]string{}
	ents, _ := fs.ReadDir(builtinFS, "builtin")
	for _, e := range ents {
		data, err := fs.ReadFile(builtinFS, "builtin/"+e.Name())
		if err != nil {
			continue
		}
		if d, err := Parse(data, time.UTC); err == nil {
			out[d.ID] = string(data)
		}
	}
	return out
}
