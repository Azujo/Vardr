// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Node to węzeł drzewa warunków: ocena zdarzenia w Go (silnik w locie)
// i warunek SQL (silnik zapytań, sql.go).
type Node interface {
	Eval(e Event) bool
	sql() string
}

type and []Node

func (n and) Eval(e Event) bool {
	for _, c := range n {
		if !c.Eval(e) {
			return false
		}
	}
	return true
}

type or []Node

func (n or) Eval(e Event) bool {
	for _, c := range n {
		if c.Eval(e) {
			return true
		}
	}
	return false
}

type not struct{ n Node }

func (n not) Eval(e Event) bool { return !n.n.Eval(e) }

type always bool

func (a always) Eval(Event) bool { return bool(a) }

// ---- logsource ----

var services = map[string]string{
	"security":      "security",
	"system":        "system",
	"application":   "application",
	"sysmon":        "microsoft-windows-sysmon/operational",
	"powershell":    "microsoft-windows-powershell/operational",
	"windefend":     "microsoft-windows-windows defender/operational",
	"taskscheduler": "microsoft-windows-taskscheduler/operational",
}

type channelIs string

func (c channelIs) Eval(e Event) bool {
	v, _ := e.Get("Channel")
	return strings.EqualFold(v, string(c))
}

type codeIs uint32

func (c codeIs) Eval(e Event) bool { return e.Code == uint32(c) }

func onChannel(ch string, codes ...uint32) Node {
	if len(codes) == 0 {
		return channelIs(ch)
	}
	o := or{}
	for _, c := range codes {
		o = append(o, codeIs(c))
	}
	return and{channelIs(ch), o}
}

// products: produkt Sigmy → prefiks event.dataset zdarzeń z tego źródła.
var products = map[string]string{
	"windows":   "windows.",
	"fortigate": "fortinet.fortigate",
	"fortinet":  "fortinet.fortigate",
	"mikrotik":  "mikrotik.routeros",
	"routeros":  "mikrotik.routeros",
	"azure":     "azure.",
	"entra":     "azure.",
}

// azureServices: usługa Sigmy dla product: azure → zbiór danych.
var azureServices = map[string]string{
	"signinlogs": "azure.signinlogs",
	"auditlogs":  "azure.auditlogs",
}

// datasetIs: event.dataset z rodziny produktu – prefiks zakończony kropką
// („windows.”) albo nazwa zbioru i jego podzbiory („fortinet.fortigate”,
// „fortinet.fortigate.vpn”, ale nie „fortinet.fortigatex”). Zbiory danych
// są pisane małymi literami (normalizator, dekodery), więc porównanie jest
// dokładne w obu silnikach.
type datasetIs string

func (d datasetIs) Eval(e Event) bool {
	p := string(d)
	if strings.HasSuffix(p, ".") {
		return strings.HasPrefix(e.Dataset, p)
	}
	return e.Dataset == p || strings.HasPrefix(e.Dataset, p+".")
}

func (d datasetIs) sql() string {
	p := string(d)
	if strings.HasSuffix(p, ".") {
		return fmt.Sprintf("startsWith(event_dataset, %s)", Quote(p))
	}
	return fmt.Sprintf("(event_dataset = %s OR startsWith(event_dataset, %s))", Quote(p), Quote(p+"."))
}

func compileLogsource(l logsource) (Node, error) {
	prefix, ok := products[strings.ToLower(l.Product)]
	if l.Product != "" && !ok {
		return nil, fmt.Errorf("product %q nieobsługiwany (windows, fortigate, mikrotik, azure)", l.Product)
	}
	if prefix == "azure." && l.Service != "" {
		ds, ok := azureServices[strings.ToLower(l.Service)]
		if !ok {
			return nil, fmt.Errorf("product azure: service %q nieobsługiwany (signinlogs, auditlogs)", l.Service)
		}
		if l.Category != "" {
			return nil, fmt.Errorf("product azure: category nieobsługiwana")
		}
		return and{datasetIs(ds)}, nil
	}
	if prefix != "windows." && (l.Service != "" || l.Category != "") {
		return nil, fmt.Errorf("product %s: service i category tylko dla windows i azure", l.Product)
	}
	n := and{}
	if prefix != "" {
		n = append(n, datasetIs(prefix))
	}
	if l.Service != "" {
		ch, ok := services[strings.ToLower(l.Service)]
		if !ok {
			return nil, fmt.Errorf("service %q nieobsługiwany", l.Service)
		}
		n = append(n, channelIs(ch))
	}
	switch strings.ToLower(l.Category) {
	case "":
	case "process_creation":
		n = append(n, or{onChannel(services["sysmon"], 1), onChannel("security", 4688)})
	case "ps_script":
		n = append(n, onChannel(services["powershell"], 4104))
	case "network_connection":
		n = append(n, onChannel(services["sysmon"], 3))
	case "file_event":
		n = append(n, onChannel(services["sysmon"], 11))
	case "dns_query":
		n = append(n, onChannel(services["sysmon"], 22))
	case "registry_set":
		n = append(n, onChannel(services["sysmon"], 13))
	default:
		return nil, fmt.Errorf("category %q nieobsługiwana", l.Category)
	}
	if len(n) == 0 {
		return always(true), nil
	}
	return n, nil
}

// ---- selekcje ----

func compileDetection(det map[string]any) (Node, error) {
	condRaw, ok := det["condition"]
	if !ok {
		return nil, errors.New("brak condition")
	}
	cond, ok := condRaw.(string)
	if !ok {
		return nil, errors.New("condition: jeden warunek tekstowy (listy warunków nieobsługiwane)")
	}
	sel := map[string]Node{}
	for name, v := range det {
		if name == "condition" || name == "timeframe" {
			if name == "timeframe" {
				return nil, errors.New("timeframe nieobsługiwany – progi przez vardr (etap 4c)")
			}
			continue
		}
		n, err := compileSelection(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		sel[name] = n
	}
	return parseCondition(cond, sel)
}

func compileSelection(v any) (Node, error) {
	switch s := v.(type) {
	case map[string]any:
		return compileMap(s)
	case []any:
		if len(s) == 0 {
			return nil, errors.New("pusta lista")
		}
		if _, isMap := s[0].(map[string]any); isMap {
			o := or{}
			for _, item := range s {
				m, ok := item.(map[string]any)
				if !ok {
					return nil, errors.New("lista map i wartości jednocześnie")
				}
				n, err := compileMap(m)
				if err != nil {
					return nil, err
				}
				o = append(o, n)
			}
			return o, nil
		}
		// Słowa kluczowe: wyszukiwanie w treści zdarzenia.
		ms, err := compileValues(s, "contains", false)
		if err != nil {
			return nil, err
		}
		return keywords(ms), nil
	}
	return nil, fmt.Errorf("nieobsługiwana selekcja (%T)", v)
}

func compileMap(m map[string]any) (Node, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // stała kolejność – łatwiejsze testy
	n := and{}
	for _, k := range keys {
		parts := strings.Split(k, "|")
		field, mods := parts[0], parts[1:]
		if field == "" {
			return nil, errors.New("pusta nazwa pola")
		}
		kind, all, exists := "eq", false, false
		for _, mod := range mods {
			switch mod {
			case "contains", "startswith", "endswith", "re", "cidr":
				if kind != "eq" {
					return nil, fmt.Errorf("%s: dwa modyfikatory dopasowania", k)
				}
				kind = mod
			case "all":
				all = true
			case "exists":
				exists = true
			default:
				return nil, fmt.Errorf("%s: modyfikator %q nieobsługiwany", k, mod)
			}
		}
		if exists {
			b, ok := m[k].(bool)
			if !ok {
				return nil, fmt.Errorf("%s: exists wymaga true/false", k)
			}
			n = append(n, fieldExists{field, b})
			continue
		}
		var vals []any
		switch v := m[k].(type) {
		case []any:
			vals = v
		default:
			vals = []any{v}
		}
		if len(vals) == 0 {
			return nil, fmt.Errorf("%s: pusta lista wartości", k)
		}
		ms, err := compileValues(vals, kind, true)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		n = append(n, fieldMatch{field: field, m: ms, all: all})
	}
	return n, nil
}

// matcher dopasowuje jedną wartość (tekst już małymi literami).
type matcher struct {
	kind   string // eq | contains | startswith | endswith | glob | re | cidr | null
	val    string
	re     *regexp.Regexp
	prefix netip.Prefix
}

func (m matcher) match(v string, present bool) bool {
	switch m.kind {
	case "null":
		return !present || v == ""
	case "re":
		return present && m.re.MatchString(v)
	case "cidr":
		a, err := netip.ParseAddr(strings.TrimPrefix(v, "::ffff:"))
		return present && err == nil && m.prefix.Contains(a.Unmap())
	}
	if !present {
		return false
	}
	lv := strings.ToLower(v)
	switch m.kind {
	case "eq":
		return lv == m.val
	case "contains":
		return strings.Contains(lv, m.val)
	case "startswith":
		return strings.HasPrefix(lv, m.val)
	case "endswith":
		return strings.HasSuffix(lv, m.val)
	case "glob":
		return wildcard(m.val, lv)
	}
	return false
}

func compileValues(vals []any, kind string, allowNull bool) ([]matcher, error) {
	var out []matcher
	for _, raw := range vals {
		var s string
		switch v := raw.(type) {
		case nil:
			if !allowNull {
				return nil, errors.New("null niedozwolone")
			}
			out = append(out, matcher{kind: "null"})
			continue
		case string:
			s = v
		case int:
			s = strconv.Itoa(v)
		case float64:
			s = strconv.FormatFloat(v, 'f', -1, 64)
		case bool:
			s = strconv.FormatBool(v)
		default:
			return nil, fmt.Errorf("nieobsługiwana wartość %v (%T)", raw, raw)
		}
		switch kind {
		case "re":
			re, err := regexp.Compile(s)
			if err != nil {
				return nil, fmt.Errorf("wyrażenie regularne %q: %w", s, err)
			}
			out = append(out, matcher{kind: "re", re: re})
			continue
		case "cidr":
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("cidr %q: %w", s, err)
			}
			out = append(out, matcher{kind: "cidr", prefix: p.Masked()})
			continue
		}
		ls := strings.ToLower(s)
		// Maski Sigmy (* i ?, „\*” to dosłowna gwiazdka) – własne dopasowanie;
		// ukośnik wsteczny w ścieżkach Windows zostaje zwykłym znakiem.
		if hasWildcard(ls) {
			switch kind {
			case "contains":
				ls = "*" + ls + "*"
			case "startswith":
				ls += "*"
			case "endswith":
				ls = "*" + ls
			}
			out = append(out, matcher{kind: "glob", val: ls})
			continue
		}
		ls = unescape(ls)
		out = append(out, matcher{kind: kind, val: ls})
	}
	return out, nil
}

type fieldMatch struct {
	field string
	m     []matcher
	all   bool
}

func (f fieldMatch) Eval(e Event) bool {
	v, ok := e.Get(f.field)
	for _, m := range f.m {
		hit := m.match(v, ok)
		if f.all && !hit {
			return false
		}
		if !f.all && hit {
			return true
		}
	}
	return f.all
}

type fieldExists struct {
	field string
	want  bool
}

func (f fieldExists) Eval(e Event) bool {
	v, ok := e.Get(f.field)
	return (ok && v != "") == f.want
}

// keywords: dowolne ze słów w treści zdarzenia (oryginalny XML i opis).
type keywords []matcher

func (k keywords) Eval(e Event) bool {
	text := e.Raw + "\n" + e.Message
	for _, m := range k {
		if m.match(text, true) {
			return true
		}
	}
	return false
}

// ---- warunek ----

type condParser struct {
	toks []string
	pos  int
	sel  map[string]Node
}

var condTokenRe = regexp.MustCompile(`\(|\)|\||[^\s()|]+`)

func parseCondition(cond string, sel map[string]Node) (Node, error) {
	p := &condParser{toks: condTokenRe.FindAllString(cond, -1), sel: sel}
	if slices.Contains(p.toks, "|") {
		return nil, errors.New("agregacje Sigmy („| count()…”) nieobsługiwane – progi przez vardr.threshold")
	}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("nieoczekiwane %q w warunku", p.toks[p.pos])
	}
	return n, nil
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) or() (Node, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	o := or{left}
	for strings.EqualFold(p.peek(), "or") {
		p.pos++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		o = append(o, r)
	}
	if len(o) == 1 {
		return left, nil
	}
	return o, nil
}

func (p *condParser) and() (Node, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	a := and{left}
	for strings.EqualFold(p.peek(), "and") {
		p.pos++
		r, err := p.unary()
		if err != nil {
			return nil, err
		}
		a = append(a, r)
	}
	if len(a) == 1 {
		return left, nil
	}
	return a, nil
}

func (p *condParser) unary() (Node, error) {
	t := p.peek()
	switch {
	case t == "":
		return nil, errors.New("niepełny warunek")
	case strings.EqualFold(t, "not"):
		p.pos++
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		return not{n}, nil
	case t == "(":
		p.pos++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("brak „)” w warunku")
		}
		p.pos++
		return n, nil
	case t == "1" || strings.EqualFold(t, "all") || strings.EqualFold(t, "any"):
		p.pos++
		if !strings.EqualFold(p.peek(), "of") {
			return nil, fmt.Errorf("po %q oczekiwano „of”", t)
		}
		p.pos++
		pat := p.peek()
		if pat == "" {
			return nil, errors.New("brak wzorca po „of”")
		}
		p.pos++
		var names []string
		for name := range p.sel {
			if strings.EqualFold(pat, "them") {
				names = append(names, name)
			} else if ok, _ := path.Match(pat, name); ok {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("wzorzec %q nie pasuje do żadnej selekcji", pat)
		}
		sort.Strings(names)
		var nodes []Node
		for _, n := range names {
			nodes = append(nodes, p.sel[n])
		}
		if strings.EqualFold(t, "all") {
			return and(nodes), nil
		}
		return or(nodes), nil
	}
	n, ok := p.sel[t]
	if !ok {
		return nil, fmt.Errorf("nieznana selekcja %q", t)
	}
	p.pos++
	return n, nil
}
