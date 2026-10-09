// Package decode to dekodery logów spoza Windows (syslog z zapór, routerów,
// serwerów): rozbiór nagłówka syslog, wybór dekodera po dopasowaniu
// i zamiana treści na pola zdarzenia (podzbiór ECS + mapa pól). Używany
// przez normalizator i test dekodera w panelu.
package decode

import (
	"strconv"
	"strings"
	"time"
)

// Header to rozebrany nagłówek syslog.
type Header struct {
	Facility int       // -1 = brak <PRI>
	Severity int       // -1 = brak <PRI>
	Time     time.Time // zero = brak czasu w nagłówku
	Host     string
	App      string // TAG (RFC 3164) albo APP-NAME (RFC 5424)
	PID      string
	MsgID    string
	Message  string // treść po nagłówku
	Format   string // rfc5424 | rfc3164 | bare
}

var severities = []string{"emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"}

// SeverityName: nazwa poziomu syslog.
func SeverityName(s int) string {
	if s >= 0 && s < len(severities) {
		return severities[s]
	}
	return ""
}

// ParseHeader rozbiera wiadomość syslog. Rozpoznaje RFC 5424
// („<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG”), RFC 3164
// („<PRI>Mmm dd hh:mm:ss HOST TAG[PID]: MSG”, także z rokiem albo czasem
// ISO) i wiadomości bez nagłówka po <PRI> (np. FortiGate: „<189>date=…”).
// loc: strefa czasowa dla czasu RFC 3164 (bez strefy), year: rok, gdy
// brak go w nagłówku.
func ParseHeader(raw string, loc *time.Location, now time.Time) Header {
	h := Header{Facility: -1, Severity: -1, Format: "bare"}
	s := raw
	if strings.HasPrefix(s, "<") {
		if end := strings.IndexByte(s, '>'); end > 1 && end <= 4 {
			if pri, err := strconv.Atoi(s[1:end]); err == nil && pri >= 0 && pri <= 191 {
				h.Facility, h.Severity = pri/8, pri%8
				s = s[end+1:]
			}
		}
	}
	// RFC 5424: wersja „1 ”.
	if strings.HasPrefix(s, "1 ") {
		parts := strings.SplitN(s[2:], " ", 6)
		if len(parts) == 6 {
			h.Format = "rfc5424"
			if t, err := time.Parse(time.RFC3339Nano, parts[0]); err == nil {
				h.Time = t
			}
			h.Host, h.App, h.PID, h.MsgID = nil5424(parts[1]), nil5424(parts[2]), nil5424(parts[3]), nil5424(parts[4])
			h.Message = skipSD(parts[5])
			return h
		}
	}
	// RFC 3164: „Mmm dd hh:mm:ss” (dzień ze spacją), opcjonalnie rok; albo czas ISO.
	if t, rest, ok := bsdTime(s, loc, now); ok {
		h.Format = "rfc3164"
		h.Time = t
		s = rest
		// HOST TAG: wiadomość – host to pierwsze słowo, o ile po nim jest kolejne.
		if host, after, found := strings.Cut(s, " "); found && host != "" && !strings.Contains(host, "=") {
			h.Host = host
			s = after
		}
		h.App, h.PID, h.Message = tag(s)
		return h
	}
	h.Message = strings.TrimSpace(s)
	return h
}

func nil5424(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

// skipSD pomija STRUCTURED-DATA RFC 5424 („-” albo [..][..]).
func skipSD(s string) string {
	if strings.HasPrefix(s, "- ") {
		return s[2:]
	}
	if s == "-" {
		return ""
	}
	depth, inQuote := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inQuote:
			i++
		case c == '"':
			inQuote = !inQuote
		case c == '[' && !inQuote:
			depth++
		case c == ']' && !inQuote:
			depth--
			if depth == 0 && (i+1 >= len(s) || s[i+1] != '[') {
				return strings.TrimPrefix(s[i+1:], " ")
			}
		}
	}
	return s
}

var months = map[string]time.Month{"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
	"Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

// bsdTime czyta czas z początku wiadomości RFC 3164.
func bsdTime(s string, loc *time.Location, now time.Time) (time.Time, string, bool) {
	// Czas ISO na początku (np. rsyslog z RFC3339 w formacie tradycyjnym).
	if len(s) >= 20 && s[4] == '-' && s[7] == '-' && (s[10] == 'T' || s[10] == ' ') {
		if end := strings.IndexByte(s, ' '); end >= 19 {
			if t, err := time.Parse(time.RFC3339Nano, s[:end]); err == nil {
				return t, strings.TrimPrefix(s[end:], " "), true
			}
		}
	}
	if len(s) < 15 {
		return time.Time{}, s, false
	}
	m, ok := months[s[:3]]
	if !ok || s[3] != ' ' {
		return time.Time{}, s, false
	}
	day, err := strconv.Atoi(strings.TrimSpace(s[4:6]))
	if err != nil || s[6] != ' ' {
		return time.Time{}, s, false
	}
	clock := s[7:15]
	t, err := time.Parse("15:04:05", clock)
	if err != nil {
		return time.Time{}, s, false
	}
	rest := s[15:]
	year := now.In(loc).Year()
	// Opcjonalny rok po czasie („Oct  9 12:00:00 2026 host …”) albo przed nim nie występuje w 3164.
	if len(rest) >= 5 && rest[0] == ' ' {
		if y, err := strconv.Atoi(rest[1:5]); err == nil && y > 1990 && y < 2200 && (len(rest) == 5 || rest[5] == ' ') {
			year = y
			rest = rest[5:]
		}
	}
	ts := time.Date(year, m, day, t.Hour(), t.Minute(), t.Second(), 0, loc)
	// Przełom roku: zdarzenie z grudnia odebrane w styczniu.
	if ts.After(now.Add(48 * time.Hour)) {
		ts = ts.AddDate(-1, 0, 0)
	}
	return ts, strings.TrimPrefix(rest, " "), true
}

// tag rozbiera „TAG[PID]: wiadomość”. Bez dwukropka (np. MikroTik:
// „system,info,account user admin logged in”) TAG to pierwsze słowo,
// o ile wygląda na nazwę (litery, cyfry, - _ . , /).
func tag(s string) (app, pid, msg string) {
	end := strings.IndexAny(s, ": ")
	if end <= 0 {
		return "", "", s
	}
	word := s[:end]
	if i := strings.IndexByte(word, '['); i > 0 && strings.HasSuffix(word, "]") {
		app, pid = word[:i], word[i+1:len(word)-1]
	} else {
		app = word
	}
	for _, c := range app {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.,/", c)) {
			return "", "", s
		}
	}
	rest := s[end:]
	rest = strings.TrimPrefix(rest, ":")
	return app, pid, strings.TrimPrefix(rest, " ")
}
