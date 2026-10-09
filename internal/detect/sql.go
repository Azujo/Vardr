package detect

import (
	"fmt"
	"regexp"
	"strings"

	"siem/internal/model"
)

// Kompilacja reguły do warunku SQL dla tabeli siem.events w ClickHouse
// (silnik zapytań, tryb index_query). Każdy węzeł drzewa ma odpowiednik
// o tej samej semantyce co Eval – zgodność obu silników sprawdza test
// zgodności (detector/compat_test.go) na prawdziwym ClickHouse.
//
// Znane różnice (udokumentowane w README):
//   - słowa kluczowe przeszukują surowy XML, który w ClickHouse ma krótszą
//     retencję (SIEM_RAW_TTL_DAYS) – po niej szukają tylko w opisie;
//   - czas zdarzenia w ClickHouse ma dokładność milisekund.

// SQL zwraca warunek WHERE odpowiadający regule (logsource i detection).
func (r *Rule) SQL() string { return r.match.sql() }

// FieldSQL zwraca wyrażenie wartości pola (jak Event.Get – brak pola to ”).
func FieldSQL(field string) string {
	v, _ := fieldSQL(field)
	return v
}

// GroupKeySQL zwraca wyrażenie klucza alertu (jak GroupKey – małe litery,
// pola w kolejności GroupBy) jako krotkę tekstów.
func (r *Rule) GroupKeySQL() string {
	if len(r.Heimdall.GroupBy) == 0 {
		return "tuple('')"
	}
	parts := make([]string, len(r.Heimdall.GroupBy))
	for i, f := range r.Heimdall.GroupBy {
		parts[i] = "lowerUTF8(" + FieldSQL(f) + ")"
	}
	return "tuple(" + strings.Join(parts, ", ") + ")"
}

// Quote zapisuje tekst jako literał SQL ClickHouse.
func Quote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// EventColumns: kolumny siem.events składające się na zdarzenie (kolejność
// jak w EventDest) – silnik zapytań i test reguły w panelu.
const EventColumns = `timestamp, ingested, event_id, agent_id, event_dataset, event_code, event_provider, event_action,
	event_outcome, host_name, user_name, user_domain, ` + IPExpr + `, process_name, process_command_line,
	message, fields, raw`

// EventDest: miejsca na kolumny EventColumns (rows.Scan).
func EventDest(e *model.Event) []any {
	return []any{&e.Timestamp, &e.Ingested, &e.ID, &e.AgentID, &e.Dataset, &e.Code, &e.Provider, &e.Action,
		&e.Outcome, &e.HostName, &e.UserName, &e.UserDomain, &e.SourceIP, &e.ProcessName, &e.CommandLine,
		&e.Message, &e.Fields, &e.Raw}
}

// IPExpr: adres źródłowy jak w zdarzeniu (IPv4 bez ::ffff:, brak – ”).
const IPExpr = `if(source_ip = toIPv6('::'), '', replaceRegexpOne(toString(source_ip), '^::ffff:', ''))`

func column(c string) (string, string) { return c, c + " != ''" }

// fieldSQL: wartość i obecność pola – odpowiednik Event.Get.
func fieldSQL(field string) (val, present string) {
	switch field {
	case "EventID", "event.code", "event_code":
		return "toString(event_code)", "1"
	case "Channel", "winlog.channel":
		return "fields['winlog.channel']", "mapContains(fields, 'winlog.channel')"
	case "Provider_Name", "event.provider":
		return column("event_provider")
	case "Computer", "host.name", "Hostname":
		return column("host_name")
	case "event.dataset":
		return "event_dataset", "1"
	case "event.action":
		return column("event_action")
	case "event.outcome":
		return column("event_outcome")
	case "user.name":
		return column("user_name")
	case "user.domain":
		return column("user_domain")
	case "source.ip":
		return IPExpr, IPExpr + " != ''"
	case "process.name":
		return column("process_name")
	case "process.command_line":
		return column("process_command_line")
	case "agent.id":
		return "agent_id", "1"
	case "message":
		return column("message")
	}
	names := aliases[field]
	if names == nil {
		names = []string{field}
	}
	// Ostatnia próba (jak w Get): nazwa pola bez względu na wielkość liter.
	ci := fmt.Sprintf("arrayFirst(k -> lowerUTF8(k) = %s, mapKeys(fields))", Quote(strings.ToLower(field)))
	var cases, pres []string
	for _, n := range names {
		has := fmt.Sprintf("mapContains(fields, %s)", Quote(n))
		cases = append(cases, has, fmt.Sprintf("fields[%s]", Quote(n)))
		pres = append(pres, has)
	}
	pres = append(pres, fmt.Sprintf("arrayExists(k -> lowerUTF8(k) = %s, mapKeys(fields))", Quote(strings.ToLower(field))))
	val = fmt.Sprintf("multiIf(%s, fields[%s])", strings.Join(cases, ", "), ci)
	return val, "(" + strings.Join(pres, " OR ") + ")"
}

func joinSQL(parts []string, op, empty string) string {
	if len(parts) == 0 {
		return empty
	}
	return "(" + strings.Join(parts, " "+op+" ") + ")"
}

func (n and) sql() string {
	parts := make([]string, len(n))
	for i, c := range n {
		parts[i] = c.sql()
	}
	return joinSQL(parts, "AND", "1")
}

func (n or) sql() string {
	parts := make([]string, len(n))
	for i, c := range n {
		parts[i] = c.sql()
	}
	return joinSQL(parts, "OR", "0")
}

func (n not) sql() string { return "(NOT " + n.n.sql() + ")" }

func (a always) sql() string {
	if a {
		return "1"
	}
	return "0"
}

func (c channelIs) sql() string {
	return fmt.Sprintf("(lowerUTF8(fields['winlog.channel']) = %s)", Quote(strings.ToLower(string(c))))
}

func (c codeIs) sql() string { return fmt.Sprintf("(event_code = %d)", uint32(c)) }

// globRE zamienia maskę Sigmy (już małymi literami) na wyrażenie RE2.
func globRE(pat string) string {
	var b strings.Builder
	b.WriteString("(?s)^")
	for i := 0; i < len(pat); {
		switch {
		case isEscape(pat, i):
			b.WriteString(regexp.QuoteMeta(pat[i+1 : i+2]))
			i += 2
			continue
		case pat[i] == '*':
			b.WriteString(".*")
		case pat[i] == '?':
			b.WriteString(".")
		default:
			r := []rune(pat[i:])[0]
			b.WriteString(regexp.QuoteMeta(string(r)))
			i += len(string(r))
			continue
		}
		i++
	}
	b.WriteString("$")
	return b.String()
}

// sql: warunek dopasowania wartości val (obecnej, gdy present).
func (m matcher) sql(val, present string) string {
	lv := "lowerUTF8(" + val + ")"
	var cond string
	switch m.kind {
	case "null":
		return fmt.Sprintf("(NOT %s OR %s = '')", present, val)
	case "re":
		cond = fmt.Sprintf("match(%s, %s)", val, Quote(m.re.String()))
	case "cidr":
		a := fmt.Sprintf("replaceRegexpOne(%s, '^::ffff:', '')", val)
		cond = fmt.Sprintf("if(isIPv4String(%[1]s) OR isIPv6String(%[1]s), isIPAddressInRange(%[1]s, %[2]s), 0)",
			a, Quote(m.prefix.String()))
	case "eq":
		cond = fmt.Sprintf("%s = %s", lv, Quote(m.val))
	case "contains":
		cond = fmt.Sprintf("position(%s, %s) > 0", lv, Quote(m.val))
	case "startswith":
		cond = fmt.Sprintf("startsWith(%s, %s)", lv, Quote(m.val))
	case "endswith":
		cond = fmt.Sprintf("endsWith(%s, %s)", lv, Quote(m.val))
	case "glob":
		cond = fmt.Sprintf("match(%s, %s)", lv, Quote(globRE(m.val)))
	default:
		return "0"
	}
	if present == "1" {
		return "(" + cond + ")"
	}
	return fmt.Sprintf("(%s AND %s)", present, cond)
}

func (f fieldMatch) sql() string {
	val, present := fieldSQL(f.field)
	parts := make([]string, len(f.m))
	for i, m := range f.m {
		parts[i] = m.sql(val, present)
	}
	if f.all {
		return joinSQL(parts, "AND", "1")
	}
	return joinSQL(parts, "OR", "0")
}

func (f fieldExists) sql() string {
	val, present := fieldSQL(f.field)
	c := fmt.Sprintf("(%s AND %s != '')", present, val)
	if f.want {
		return c
	}
	return "(NOT " + c + ")"
}

func (k keywords) sql() string {
	parts := make([]string, len(k))
	for i, m := range k {
		parts[i] = m.sql("concat(raw, '\\n', message)", "1")
	}
	return joinSQL(parts, "OR", "0")
}
