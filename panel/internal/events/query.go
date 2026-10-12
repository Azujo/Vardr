// Package events to wyszukiwarka zdarzeń panelu (Mímir): prosty język
// zapytań, budowa bezpiecznego SQL (tylko kolumny z listy, wartości jako
// parametry) i zapytania do ClickHouse.
package events

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Język zapytań (przykłady):
//
//	user:jkowalski code:4625            pole:wartość (wiele warunków = I)
//	host:pc0*                           prefiks
//	-action:logged-out                  negacja
//	"invoke-expression"  powershell     tekst w treści zdarzenia (message i surowy XML)
//	fields.TargetUserName:admin         pole źródłowe zdarzenia (mapa fields)
//	ip:10.0.5.23                        adres źródłowy

type fieldKind int

const (
	kindString  fieldKind = iota // równość lub prefiks
	kindLowCard                  // jak string (LowCardinality)
	kindNumber                   // równość liczbowa
	kindIP                       // adres IP
)

type field struct {
	column string
	kind   fieldKind
	help   string
}

// Fields to pola dostępne w zapytaniach (nazwa → kolumna siem.events).
var Fields = map[string]field{
	"host":     {"host_name", kindLowCard, "nazwa komputera (małe litery)"},
	"agent":    {"agent_id", kindLowCard, "identyfikator agenta"},
	"user":     {"user_name", kindString, "użytkownik"},
	"domain":   {"user_domain", kindLowCard, "domena użytkownika"},
	"identity": {"user_identity", kindLowCard, "osoba (to samo konto w AD, Entra, na VPN)"},
	"ip":       {"source_ip", kindIP, "adres źródłowy"},
	"code":     {"event_code", kindNumber, "Event ID Windows"},
	"action":   {"event_action", kindLowCard, "akcja, np. logon-failed"},
	"outcome":  {"event_outcome", kindLowCard, "success / failure"},
	"dataset":  {"event_dataset", kindLowCard, "źródło, np. windows.security"},
	"provider": {"event_provider", kindLowCard, "dostawca zdarzenia"},
	"process":  {"process_name", kindString, "ścieżka procesu"},
}

// Aliasy pól.
var aliases = map[string]string{"id": "code", "eventid": "code", "channel": "dataset", "src": "ip", "computer": "host",
	"osoba": "identity", "person": "identity"}

var fieldsKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// Condition to warunek SQL z parametrami.
type Condition struct {
	SQL  string
	Args []any
}

// Parsed to sparsowane zapytanie.
type Parsed struct {
	Conds []Condition
	Text  []string // słowa i frazy do wyszukania w treści
	// Replay: szukanie w zdarzeniach odtworzonych z archiwum
	// (siem.events_replay) zamiast w bieżących (siem.events).
	Replay bool
}

// Parse zamienia tekst zapytania na warunki SQL. Nazwy kolumn pochodzą
// wyłącznie z listy Fields – użytkownik podaje tylko wartości (parametry).
func Parse(q string) (Parsed, error) {
	var p Parsed
	tokens, err := tokenize(q)
	if err != nil {
		return p, err
	}
	for _, t := range tokens {
		if !t.quoted {
			if name, value, ok := strings.Cut(t.text, ":"); ok && name != "" && value != "" && isFieldName(strings.TrimPrefix(name, "-")) {
				c, err := fieldCondition(name, value)
				if err != nil {
					return p, err
				}
				p.Conds = append(p.Conds, c)
				continue
			}
		}
		text := strings.TrimSpace(t.text)
		if text == "" {
			continue
		}
		if len([]rune(text)) > 200 {
			return p, errors.New("fraza do wyszukania jest za długa (maks. 200 znaków)")
		}
		p.Text = append(p.Text, text)
	}
	if len(p.Conds)+len(p.Text) > 20 {
		return p, errors.New("za dużo warunków w zapytaniu (maks. 20)")
	}
	return p, nil
}

func isFieldName(name string) bool {
	if strings.HasPrefix(name, "fields.") {
		return true
	}
	name = strings.ToLower(name)
	if a, ok := aliases[name]; ok {
		name = a
	}
	_, ok := Fields[name]
	return ok
}

func fieldCondition(name, value string) (Condition, error) {
	neg := strings.HasPrefix(name, "-")
	name = strings.TrimPrefix(name, "-")
	wrap := func(c Condition) Condition {
		if neg {
			c.SQL = "NOT (" + c.SQL + ")"
		}
		return c
	}
	if key, ok := strings.CutPrefix(name, "fields."); ok {
		if !fieldsKeyPattern.MatchString(key) {
			return Condition{}, fmt.Errorf("niepoprawna nazwa pola %q", key)
		}
		if v, prefix := strings.CutSuffix(value, "*"); prefix {
			return wrap(Condition{"startsWith(fields[?], ?)", []any{key, v}}), nil
		}
		return wrap(Condition{"fields[?] = ?", []any{key, value}}), nil
	}
	lname := strings.ToLower(name)
	if a, ok := aliases[lname]; ok {
		lname = a
	}
	f := Fields[lname]
	switch f.kind {
	case kindNumber:
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return Condition{}, fmt.Errorf("%s: oczekiwano liczby, a jest %q", lname, value)
		}
		return wrap(Condition{f.column + " = ?", []any{uint32(n)}}), nil
	case kindIP:
		if strings.ContainsAny(value, "*") {
			return Condition{}, errors.New("ip: prefiks nie jest obsługiwany – podaj pełny adres")
		}
		return wrap(Condition{f.column + " = toIPv6OrDefault(?)", []any{value}}), nil
	default:
		if lname == "host" {
			value = strings.ToLower(value) // nazwy hostów zapisujemy małymi literami
		}
		if v, prefix := strings.CutSuffix(value, "*"); prefix {
			return wrap(Condition{"startsWith(" + f.column + ", ?)", []any{v}}), nil
		}
		return wrap(Condition{f.column + " = ?", []any{value}}), nil
	}
}

type token struct {
	text   string
	quoted bool
}

// tokenize dzieli zapytanie na słowa; "fraza w cudzysłowie" to jedno słowo.
func tokenize(q string) ([]token, error) {
	var out []token
	var cur strings.Builder
	inQuote := false
	flush := func(quoted bool) {
		if cur.Len() > 0 || quoted {
			out = append(out, token{cur.String(), quoted})
		}
		cur.Reset()
	}
	for _, r := range q {
		switch {
		case r == '"':
			if inQuote {
				flush(true)
			} else {
				flush(false)
			}
			inQuote = !inQuote
		case unicode.IsSpace(r) && !inQuote:
			flush(false)
		default:
			cur.WriteRune(r)
		}
	}
	if inQuote {
		return nil, errors.New("niezamknięty cudzysłów w zapytaniu")
	}
	flush(false)
	return out, nil
}

// TextCondition zamienia słowa do wyszukania na warunek: każde słowo musi
// wystąpić w opisie albo w surowym XML (bez rozróżniania wielkości liter).
func (p Parsed) TextCondition() (Condition, bool) {
	if len(p.Text) == 0 {
		return Condition{}, false
	}
	var parts []string
	var args []any
	for _, t := range p.Text {
		parts = append(parts, "(positionCaseInsensitiveUTF8(message, ?) > 0 OR positionCaseInsensitiveUTF8(raw, ?) > 0)")
		args = append(args, t, t)
	}
	return Condition{strings.Join(parts, " AND "), args}, true
}

// FieldHelp zwraca opis pól (do podpowiedzi w panelu).
func FieldHelp() []map[string]string {
	var out []map[string]string
	for name, f := range Fields {
		out = append(out, map[string]string{"name": name, "help": f.help})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"] < out[j]["name"] })
	return out
}
