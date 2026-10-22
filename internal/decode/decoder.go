// SPDX-License-Identifier: AGPL-3.0-or-later

package decode

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Def to definicja dekodera (YAML: wbudowane w internal/decode/builtin,
// później także z panelu).
type Def struct {
	ID          string            `yaml:"id" json:"id"`
	Title       string            `yaml:"title" json:"title"`
	Description string            `yaml:"description" json:"description,omitempty"`
	Version     int               `yaml:"version" json:"version"`
	Priority    int               `yaml:"priority" json:"priority"` // wyższy sprawdzany wcześniej
	Dataset     string            `yaml:"dataset" json:"dataset"`
	Match       MatchDef          `yaml:"match" json:"match"`
	Parser      ParserDef         `yaml:"parser" json:"parser"`
	Fields      map[string]StrSet `yaml:"fields" json:"fields,omitempty"`
	Outcome     *OutcomeDef       `yaml:"outcome" json:"outcome,omitempty"`
	// Set: stałe wartości pól dla każdej wiadomości dekodera (np.
	// event.action: sign-in); mapowanie z treści (fields) ma pierwszeństwo.
	Set     map[string]string `yaml:"set" json:"set,omitempty"`
	Time    *TimeDef          `yaml:"time" json:"time,omitempty"`
	Samples []string          `yaml:"samples" json:"samples,omitempty"` // przykłady (test i dokumentacja)
}

// MatchDef: wszystkie podane warunki muszą być spełnione; Any – dodatkowo
// co najmniej jedna z alternatyw (np. tematy RouterOS w nagłówku albo nazwa
// hosta albo charakterystyczna treść).
type MatchDef struct {
	Peer     []string   `yaml:"peer" json:"peer,omitempty"`           // sieci nadawców (CIDR)
	Host     []string   `yaml:"host" json:"host,omitempty"`           // nazwa hosta z nagłówka (bez wielkości liter)
	App      []string   `yaml:"app" json:"app,omitempty"`             // nazwa programu z nagłówka (bez wielkości liter)
	AppRegex string     `yaml:"app_regex" json:"app_regex,omitempty"` // RE2 na nazwie programu
	Contains []string   `yaml:"contains" json:"contains,omitempty"`   // fragmenty treści (wszystkie)
	Regex    string     `yaml:"regex" json:"regex,omitempty"`         // RE2 na treści
	Any      []MatchDef `yaml:"any" json:"any,omitempty"`             // alternatywy (bez zagnieżdżania)
}

// ParserDef to sposób rozbioru treści.
type ParserDef struct {
	Type      string       `yaml:"type" json:"type"`                     // kv | json | csv | regex | none
	Separator string       `yaml:"separator" json:"separator,omitempty"` // csv
	Columns   []string     `yaml:"columns" json:"columns,omitempty"`     // csv
	Patterns  []PatternDef `yaml:"patterns" json:"patterns,omitempty"`   // regex: pierwszy pasujący
}

// PatternDef to wzorzec parsera regex: grupy nazwane to pola, Set – stałe
// wartości (np. event.action) dla tego wzorca.
type PatternDef struct {
	Regex string            `yaml:"regex" json:"regex"`
	Set   map[string]string `yaml:"set" json:"set,omitempty"`
}

// OutcomeDef wyznacza event.outcome z wartości pola.
type OutcomeDef struct {
	Field   StrSet   `yaml:"field" json:"field"` // pierwsze niepuste z listy
	Failure []string `yaml:"failure" json:"failure,omitempty"`
	Success []string `yaml:"success" json:"success,omitempty"`
	// Otherwise: wynik, gdy pole ma wartość spoza list (np. kod błędu
	// logowania: 0 – success, każdy inny – failure).
	Otherwise string `yaml:"otherwise" json:"otherwise,omitempty"`
}

// TimeDef: czas zdarzenia z pól treści (lepszy niż czas z nagłówka).
type TimeDef struct {
	Fields   []string `yaml:"fields" json:"fields"`               // łączone spacją
	Layout   string   `yaml:"layout" json:"layout"`               // układ Go albo unix | unix_ms | unix_ns | rfc3339
	Timezone string   `yaml:"timezone" json:"timezone,omitempty"` // gdy czas bez strefy (domyślnie strefa serwera)
}

// StrSet to jedna nazwa albo lista nazw w YAML.
type StrSet []string

func (s *StrSet) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*s = StrSet{n.Value}
		return nil
	}
	var l []string
	if err := n.Decode(&l); err != nil {
		return err
	}
	*s = l
	return nil
}

// Decoder to skompilowany dekoder.
type Decoder struct {
	Def
	match    matcher
	any      []matcher
	patterns []*regexp.Regexp
	loc      *time.Location
}

// matcher to skompilowany MatchDef (bez Any).
type matcher struct {
	peers    []netip.Prefix
	hosts    map[string]bool
	apps     map[string]bool
	re       *regexp.Regexp
	appRe    *regexp.Regexp
	contains []string
}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	datasetRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,99}$`)
)

// Targets: pola zdarzenia, do których dekoder może przypisać wartość
// (pozostałe nazwy trafiają do mapy pól pod tą nazwą).
var Targets = []string{"host.name", "user.name", "user.domain", "source.ip", "process.name", "process.command_line",
	"message", "event.action", "event.outcome", "event.code", "event.provider"}

// Compile sprawdza i kompiluje definicję.
func Compile(d Def, defaultLoc *time.Location) (*Decoder, error) {
	dec := &Decoder{Def: d, loc: defaultLoc}
	switch {
	case !idRe.MatchString(d.ID):
		return nil, errors.New("id: 2–64 znaki: małe litery, cyfry, . _ -")
	case d.Title == "":
		return nil, errors.New("brak title")
	case !datasetRe.MatchString(d.Dataset):
		return nil, errors.New("dataset: małe litery, cyfry, . _ - (np. fortinet.fortigate)")
	case strings.HasPrefix(d.Dataset, "windows.") || d.Dataset == "syslog.generic":
		// Reguły Windows działają na windows.*; zdarzenia z syslog nie mogą
		// się pod nie podszyć (ani pod zdarzenia bez dekodera).
		return nil, errors.New("dataset: windows.* i syslog.generic są zarezerwowane")
	}
	m, err := compileMatch(d.Match, "match")
	if err != nil {
		return nil, err
	}
	dec.match = m
	for i, alt := range d.Match.Any {
		if len(alt.Any) > 0 {
			return nil, fmt.Errorf("match.any[%d]: bez zagnieżdżonego any", i)
		}
		am, err := compileMatch(alt, fmt.Sprintf("match.any[%d]", i))
		if err != nil {
			return nil, err
		}
		if am.empty() {
			return nil, fmt.Errorf("match.any[%d]: pusta alternatywa", i)
		}
		dec.any = append(dec.any, am)
	}
	if m.empty() && len(dec.any) == 0 {
		return nil, errors.New("match: podaj co najmniej jeden warunek (peer, host, app, contains, regex, any)")
	}
	switch d.Parser.Type {
	case "kv", "json", "none":
	case "csv":
		if len(d.Parser.Columns) == 0 {
			return nil, errors.New("parser csv: podaj columns")
		}
		if len([]rune(d.Parser.Separator)) > 1 {
			return nil, errors.New("parser csv: separator to jeden znak")
		}
	case "regex":
		if len(d.Parser.Patterns) == 0 {
			return nil, errors.New("parser regex: podaj patterns")
		}
		for i, p := range d.Parser.Patterns {
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				return nil, fmt.Errorf("parser.patterns[%d]: %w", i, err)
			}
			dec.patterns = append(dec.patterns, re)
		}
	default:
		return nil, errors.New("parser.type: kv, json, csv, regex albo none")
	}
	if d.Time != nil {
		if len(d.Time.Fields) == 0 || d.Time.Layout == "" {
			return nil, errors.New("time: podaj fields i layout")
		}
		if d.Time.Timezone != "" {
			loc, err := time.LoadLocation(d.Time.Timezone)
			if err != nil {
				return nil, fmt.Errorf("time.timezone: %w", err)
			}
			dec.loc = loc
		}
	}
	if d.Outcome != nil && len(d.Outcome.Field) == 0 {
		return nil, errors.New("outcome.field: podaj pole")
	}
	if d.Outcome != nil && d.Outcome.Otherwise != "" && d.Outcome.Otherwise != "success" && d.Outcome.Otherwise != "failure" {
		return nil, errors.New("outcome.otherwise: success albo failure")
	}
	return dec, nil
}

// Parse wczytuje definicję z YAML (nieznane klucze to błąd).
func Parse(data []byte, defaultLoc *time.Location) (*Decoder, error) {
	var d Def
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("YAML: %w", err)
	}
	return Compile(d, defaultLoc)
}

func compileMatch(md MatchDef, name string) (matcher, error) {
	m := matcher{hosts: map[string]bool{}, apps: map[string]bool{}, contains: md.Contains}
	for _, p := range md.Peer {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			if a, err2 := netip.ParseAddr(p); err2 == nil {
				pfx = netip.PrefixFrom(a, a.BitLen())
			} else {
				return m, fmt.Errorf("%s.peer %q: %w", name, p, err)
			}
		}
		m.peers = append(m.peers, pfx.Masked())
	}
	for _, h := range md.Host {
		m.hosts[strings.ToLower(h)] = true
	}
	for _, a := range md.App {
		m.apps[strings.ToLower(a)] = true
	}
	var err error
	if md.Regex != "" {
		if m.re, err = regexp.Compile(md.Regex); err != nil {
			return m, fmt.Errorf("%s.regex: %w", name, err)
		}
	}
	if md.AppRegex != "" {
		if m.appRe, err = regexp.Compile(md.AppRegex); err != nil {
			return m, fmt.Errorf("%s.app_regex: %w", name, err)
		}
	}
	return m, nil
}

func (m *matcher) empty() bool {
	return len(m.peers) == 0 && len(m.hosts) == 0 && len(m.apps) == 0 && len(m.contains) == 0 && m.re == nil && m.appRe == nil
}

func (m *matcher) matches(h Header, peer netip.Addr) bool {
	if len(m.peers) > 0 {
		ok := false
		for _, p := range m.peers {
			if peer.IsValid() && p.Contains(peer.Unmap()) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.hosts) > 0 && !m.hosts[strings.ToLower(h.Host)] {
		return false
	}
	if len(m.apps) > 0 && !m.apps[strings.ToLower(h.App)] {
		return false
	}
	if m.appRe != nil && !m.appRe.MatchString(h.App) {
		return false
	}
	for _, c := range m.contains {
		if !strings.Contains(h.Message, c) {
			return false
		}
	}
	return m.re == nil || m.re.MatchString(h.Message)
}

// Matches mówi, czy dekoder pasuje do wiadomości.
func (d *Decoder) Matches(h Header, peer netip.Addr) bool {
	if !d.match.matches(h, peer) {
		return false
	}
	if len(d.any) == 0 {
		return true
	}
	for i := range d.any {
		if d.any[i].matches(h, peer) {
			return true
		}
	}
	return false
}

// Result to wynik dekodowania: pola docelowe i wszystkie pola treści.
type Result struct {
	Targets map[string]string // host.name, user.name, … (Targets)
	Fields  map[string]string // pola z treści i z mapowania (nazwy spoza Targets)
	Time    time.Time         // zero = brak czasu w treści
}

// Decode rozbiera treść wiadomości. Błąd = treść nie pasuje do parsera
// (np. niepoprawny JSON) – zdarzenie trafia do kwarantanny z powodem.
func (d *Decoder) Decode(h Header) (Result, error) {
	res := Result{Targets: map[string]string{}, Fields: map[string]string{}}
	switch d.Parser.Type {
	case "kv":
		parseKV(h.Message, res.Fields)
	case "json":
		var v any
		if err := json.Unmarshal([]byte(h.Message), &v); err != nil {
			return res, fmt.Errorf("niepoprawny JSON: %w", err)
		}
		flatten("", v, res.Fields)
	case "csv":
		r := csv.NewReader(strings.NewReader(h.Message))
		if d.Parser.Separator != "" {
			r.Comma = []rune(d.Parser.Separator)[0]
		}
		r.LazyQuotes, r.FieldsPerRecord = true, -1
		rec, err := r.Read()
		if err != nil {
			return res, fmt.Errorf("niepoprawny CSV: %w", err)
		}
		for i, c := range d.Parser.Columns {
			if i < len(rec) && c != "" && c != "-" {
				res.Fields[c] = rec[i]
			}
		}
	case "regex":
		matched := false
		for i, re := range d.patterns {
			m := re.FindStringSubmatch(h.Message)
			if m == nil {
				continue
			}
			for j, name := range re.SubexpNames() {
				if name != "" && m[j] != "" {
					res.Fields[name] = m[j]
				}
			}
			for k, v := range d.Parser.Patterns[i].Set {
				res.Fields[k] = v
			}
			matched = true
			break
		}
		if !matched {
			res.Fields["decoder.pattern"] = "none" // dekoder pasuje, ale żaden wzorzec – zostaje treść
		}
	}
	for k, v := range d.Set {
		res.Targets[k] = v
	}
	// Mapowanie: cel ← pierwsze niepuste pole źródłowe (albo wartość ustawiona przez wzorzec).
	for target, srcs := range d.Fields {
		for _, src := range srcs {
			if v := res.Fields[src]; v != "" && v != "-" && v != "N/A" {
				res.Targets[target] = v
				break
			}
		}
	}
	for _, t := range Targets {
		if v, ok := res.Fields[t]; ok && res.Targets[t] == "" {
			res.Targets[t] = v // wzorzec regex ustawił cel wprost (set: event.action …)
		}
	}
	if o := d.Outcome; o != nil && res.Targets["event.outcome"] == "" {
		v := ""
		for _, f := range o.Field {
			if v = strings.ToLower(res.Fields[f]); v != "" {
				break
			}
		}
		for _, f := range o.Failure {
			if v == strings.ToLower(f) {
				res.Targets["event.outcome"] = "failure"
			}
		}
		for _, s := range o.Success {
			if v == strings.ToLower(s) {
				res.Targets["event.outcome"] = "success"
			}
		}
		if res.Targets["event.outcome"] == "" && v != "" {
			res.Targets["event.outcome"] = o.Otherwise
		}
	}
	if t := d.Time; t != nil {
		var parts []string
		for _, f := range t.Fields {
			if v := res.Fields[f]; v != "" {
				parts = append(parts, v)
			}
		}
		if len(parts) == len(t.Fields) {
			if ts, ok := parseTime(strings.Join(parts, " "), t.Layout, d.loc); ok {
				res.Time = ts
			}
		}
	}
	return res, nil
}

func parseTime(v, layout string, loc *time.Location) (time.Time, bool) {
	switch layout {
	case "unix", "unix_ms", "unix_ns":
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		switch layout {
		case "unix":
			return time.Unix(n, 0).UTC(), true
		case "unix_ms":
			return time.UnixMilli(n).UTC(), true
		}
		return time.Unix(0, n).UTC(), true
	case "rfc3339":
		t, err := time.Parse(time.RFC3339Nano, v)
		return t.UTC(), err == nil
	}
	t, err := time.ParseInLocation(layout, v, loc)
	return t.UTC(), err == nil
}

// parseKV: pary klucz=wartość rozdzielone białymi znakami; wartość
// w cudzysłowie może zawierać spacje (\" – cudzysłów w wartości).
func parseKV(s string, out map[string]string) {
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			for i < len(s) && s[i] != ' ' {
				i++
			}
			continue
		}
		key := s[start:i]
		i++
		var val strings.Builder
		if i < len(s) && s[i] == '"' {
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				val.WriteByte(s[i])
				i++
			}
			i++
		} else {
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				val.WriteByte(s[i])
				i++
			}
		}
		if key != "" {
			out[key] = val.String()
		}
	}
}

func flatten(prefix string, v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flatten(key, vv, out)
		}
	case []any:
		// Cała tablica jako JSON (wyszukiwanie „contains”) i pierwsze elementy
		// z indeksem (np. targetResources.0.userPrincipalName).
		b, _ := json.Marshal(x)
		out[prefix] = string(b)
		for i, v := range x[:min(len(x), 10)] {
			flatten(prefix+"."+strconv.Itoa(i), v, out)
		}
	case string:
		out[prefix] = x
	case nil:
	case float64:
		out[prefix] = strconv.FormatFloat(x, 'f', -1, 64)
	default:
		out[prefix] = fmt.Sprint(x)
	}
}

// Set to zestaw dekoderów w kolejności sprawdzania.
type Set struct {
	list []*Decoder
}

// NewSet porządkuje dekodery: wyższy priorytet pierwszy, potem id.
func NewSet(ds []*Decoder) *Set {
	l := append([]*Decoder(nil), ds...)
	sort.SliceStable(l, func(i, j int) bool {
		if l[i].Priority != l[j].Priority {
			return l[i].Priority > l[j].Priority
		}
		return l[i].ID < l[j].ID
	})
	return &Set{list: l}
}

// Find zwraca pierwszy pasujący dekoder (nil = brak).
func (s *Set) Find(h Header, peer netip.Addr) *Decoder {
	if s == nil {
		return nil
	}
	for _, d := range s.list {
		if d.Matches(h, peer) {
			return d
		}
	}
	return nil
}

// List zwraca dekodery w kolejności sprawdzania.
func (s *Set) List() []*Decoder { return s.list }

// LoadFS wczytuje dekodery *.yml z systemu plików (np. wbudowane).
func LoadFS(fsys fs.FS, loc *time.Location) ([]*Decoder, error) {
	var out []*Decoder
	seen := map[string]bool{}
	err := fs.WalkDir(fsys, ".", func(p string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() || !(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		d, err := Parse(data, loc)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if seen[d.ID] {
			return fmt.Errorf("%s: id %s użyte dwa razy", p, d.ID)
		}
		seen[d.ID] = true
		out = append(out, d)
		return nil
	})
	return out, err
}
