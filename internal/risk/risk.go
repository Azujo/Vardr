// SPDX-License-Identifier: AGPL-3.0-or-later

// Package risk liczy ryzyko osób i komputerów z alertów (wersja 1.3):
// wiele drobnych alertów jednej osoby, z których żaden osobno nie jest
// groźny, razem daje sygnał. Punkty za alert według poziomu, wygaszanie
// w czasie (połowa po HalfLifeDays), mnożniki dla kont uprzywilejowanych
// i komputerów krytycznych; alerty rozstrzygnięte jako fałszywy alarm albo
// uzasadnione działanie się nie liczą. Pakiet jest czysty (bez bazy):
// liczy siem-detector, panel tylko czyta wynik i ustawienia.
package risk

import (
	"math"
	"net"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"siem/internal/lang"
)

// Rodzaje encji.
const (
	User = "user" // osoba (user.identity) albo konto, gdy osoby nie ma
	Host = "host" // komputer
)

// Poziomy ryzyka od najniższego.
const (
	Low      = "low"
	Medium   = "medium"
	High     = "high"
	Critical = "critical"
)

// Levels: poziomy ryzyka od najniższego.
var Levels = []string{Low, Medium, High, Critical}

// Rozstrzygnięcia zamkniętego alertu (alerts.resolution).
const (
	TruePositive  = "true_positive"
	Benign        = "benign" // prawdziwe, ale uzasadnione działanie (np. zgłoszona praca administratora)
	FalsePositive = "false_positive"
)

// Resolutions: rozstrzygnięcia do wyboru przy zamknięciu ("" – bez).
var Resolutions = []string{TruePositive, Benign, FalsePositive}

// Config to ustawienia scoringu (panel, gjallarhorn.risk_config).
type Config struct {
	Enabled bool `json:"enabled"`
	// Points: punkty za alert danego poziomu (informational … critical).
	Points map[string]float64 `json:"points"`
	// HalfLifeDays: po ilu dniach punkty alertu spadają o połowę.
	HalfLifeDays float64 `json:"half_life_days"`
	// Thresholds: najniższy wynik poziomu (medium, high, critical).
	Thresholds map[string]float64 `json:"thresholds"`
	// PrivilegedUsers: wzorce osób i kont uprzywilejowanych (np. „*-adm”,
	// „administrator”, „adm.*@firma.pl”) – bez rozróżniania wielkości liter.
	PrivilegedUsers []string `json:"privileged_users"`
	// CriticalGroups: grupy agentów z komputerami krytycznymi (np. DC).
	CriticalGroups []int64 `json:"critical_groups"`
	// Multiplier: mnożnik punktów dla kont uprzywilejowanych i komputerów krytycznych.
	Multiplier float64 `json:"multiplier"`
	// AlertAtCritical: alert, gdy osoba albo komputer wchodzi w poziom krytyczny.
	AlertAtCritical bool `json:"alert_at_critical"`
}

// Default: ustawienia domyślne (włączone).
func Default() Config {
	return Config{
		Enabled:         true,
		Points:          map[string]float64{"informational": 0, "low": 1, "medium": 5, "high": 15, "critical": 40},
		HalfLifeDays:    14,
		Thresholds:      map[string]float64{Medium: 20, High: 50, Critical: 100},
		Multiplier:      2,
		AlertAtCritical: true,
	}
}

// Normalize uzupełnia brakujące wartości domyślnymi (konfiguracja z bazy
// sprzed dodania pola).
func (c Config) Normalize() Config {
	d := Default()
	if c.Points == nil {
		c.Points = d.Points
	}
	for k, v := range d.Points {
		if _, ok := c.Points[k]; !ok {
			c.Points[k] = v
		}
	}
	if c.Thresholds == nil {
		c.Thresholds = d.Thresholds
	}
	for k, v := range d.Thresholds {
		if _, ok := c.Thresholds[k]; !ok {
			c.Thresholds[k] = v
		}
	}
	if c.HalfLifeDays <= 0 {
		c.HalfLifeDays = d.HalfLifeDays
	}
	if c.Multiplier <= 0 {
		c.Multiplier = 1
	}
	return c
}

// Validate sprawdza ustawienia z panelu.
func (c Config) Validate() error {
	for _, l := range []string{"informational", "low", "medium", "high", "critical"} {
		if p, ok := c.Points[l]; !ok || p < 0 || p > 1000 {
			return lang.Errorf("punkty za alert: od 0 do 1000 dla każdego poziomu", "alert points: 0 to 1000 for every level")
		}
	}
	if c.HalfLifeDays < 1 || c.HalfLifeDays > 365 {
		return lang.Errorf("czas połowicznego wygaszania: od 1 do 365 dni", "half-life: 1 to 365 days")
	}
	m, h, cr := c.Thresholds[Medium], c.Thresholds[High], c.Thresholds[Critical]
	if m <= 0 || m >= h || h >= cr || cr > 100000 {
		return lang.Errorf("progi poziomów muszą rosnąć: średni < wysoki < krytyczny (powyżej 0)",
			"level thresholds must increase: medium < high < critical (above 0)")
	}
	if c.Multiplier < 1 || c.Multiplier > 10 {
		return lang.Errorf("mnożnik: od 1 do 10", "multiplier: 1 to 10")
	}
	if len(c.PrivilegedUsers) > 200 || len(c.CriticalGroups) > 200 {
		return lang.Errorf("za dużo wzorców kont albo grup", "too many account patterns or groups")
	}
	for _, p := range c.PrivilegedUsers {
		if p == "" || len(p) > 200 {
			return lang.Errorf("wzorzec konta: od 1 do 200 znaków", "account pattern: 1 to 200 characters")
		}
		if _, err := path.Match(strings.ToLower(p), ""); err != nil {
			return lang.Errorf("niepoprawny wzorzec konta %q", "invalid account pattern %q", p)
		}
	}
	return nil
}

// Input to alert do scoringu.
type Input struct {
	AlertID      int64
	RuleID       string
	RuleTitle    string
	Level        string
	LastSeen     time.Time
	HostName     string
	UserName     string
	UserIdentity string
	GroupID      int64 // grupa agenta (0 – nieznana)
	Resolution   string
}

// Contribution to wkład alertu w wynik.
type Contribution struct {
	AlertID   int64     `json:"alert_id"`
	RuleID    string    `json:"rule_id"`
	RuleTitle string    `json:"rule_title"`
	Level     string    `json:"level"`
	LastSeen  time.Time `json:"last_seen"`
	Points    float64   `json:"points"`
}

// Score to wynik osoby albo komputera.
type Score struct {
	Type    string  `json:"type"`
	Entity  string  `json:"entity"`  // klucz: osoba, konto albo komputer małymi literami
	Display string  `json:"display"` // nazwa do pokazania (jak w alercie)
	Score   float64 `json:"score"`
	Level   string  `json:"level"`
	Alerts  int     `json:"alerts"`
	// Elevated: mnożnik zastosowany (konto uprzywilejowane / komputer krytyczny).
	Elevated    bool           `json:"elevated"`
	LastAlertAt time.Time      `json:"last_alert_at"`
	Top         []Contribution `json:"top"` // największe wkłady (do 10)
}

// MaxTop: ile największych wkładów zapamiętuje wynik.
const MaxTop = 10

// Lookback: jak daleko wstecz sięgają alerty – po 8 okresach
// połowicznego wygaszania alert waży < 0,4%.
func (c Config) Lookback() time.Duration {
	return time.Duration(c.Normalize().HalfLifeDays*8*24) * time.Hour
}

// ExcludedRules: reguły, których alerty nie liczą się do ryzyka (alert
// o ryzyku krytycznym liczyłby sam siebie).
var ExcludedRules = []string{CriticalRuleID}

// CriticalRuleID: reguła wbudowana „ryzyko krytyczne”.
const CriticalRuleID = "vardr-risk-critical"

// serviceAccounts: konta systemowe – nie są osobami.
var serviceAccounts = []string{"system", "local service", "network service", "anonymous logon", "-", "n/a",
	"nt authority\\system", "nt authority\\local service", "nt authority\\network service", "nt authority\\anonymous logon"}

// UserKey: klucz osoby w alercie (tożsamość, a bez niej konto) albo ""
// dla kont systemowych i kont komputerów (NAZWA$ – ryzyko komputera).
func UserKey(identity, user string) (key, display string) {
	if identity != "" {
		return strings.ToLower(identity), identity
	}
	u := strings.TrimSpace(user)
	l := strings.ToLower(u)
	if u == "" || strings.HasSuffix(u, "$") || slices.Contains(serviceAccounts, l) {
		return "", ""
	}
	return l, u
}

// HostKey: klucz komputera – nazwa bez domeny (zdarzenia Windows podają
// pełną nazwę PC1.firma.local, inne źródła krótką PC1; to ten sam
// komputer). Adres IP zostaje w całości.
func HostKey(host string) (key, display string) {
	h := strings.TrimSpace(host)
	if h == "" || h == "-" {
		return "", ""
	}
	key = strings.ToLower(h)
	if net.ParseIP(key) == nil {
		key, _, _ = strings.Cut(key, ".")
	}
	return key, h
}

// Privileged: osoba albo konto pasuje do wzorca kont uprzywilejowanych
// (porównuje też samą nazwę bez domeny: AZUJO\jan.adm, jan.adm@firma.pl).
func (c Config) Privileged(identity, user string) bool {
	var names []string
	for _, n := range []string{identity, user} {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		names = append(names, n)
		if i := strings.LastIndex(n, `\`); i >= 0 {
			names = append(names, n[i+1:])
		}
		if i := strings.Index(n, "@"); i > 0 {
			names = append(names, n[:i])
		}
	}
	for _, p := range c.PrivilegedUsers {
		p = strings.ToLower(p)
		for _, n := range names {
			if ok, _ := path.Match(p, n); ok {
				return true
			}
		}
	}
	return false
}

// LevelOf: poziom wyniku.
func (c Config) LevelOf(score float64) string {
	switch {
	case score >= c.Thresholds[Critical]:
		return Critical
	case score >= c.Thresholds[High]:
		return High
	case score >= c.Thresholds[Medium]:
		return Medium
	}
	return Low
}

// Counts: alert liczy się do ryzyka (nie rozstrzygnięty jako fałszywy
// alarm albo uzasadnione działanie, nie z reguły wykluczonej).
func Counts(in Input) bool {
	return in.Resolution != FalsePositive && in.Resolution != Benign && !slices.Contains(ExcludedRules, in.RuleID)
}

// Compute liczy wyniki osób i komputerów z alertów. Wynik 0 (np. same
// alerty informacyjne) nie trafia na listę.
func Compute(inputs []Input, cfg Config, now time.Time) []Score {
	cfg = cfg.Normalize()
	type acc struct {
		s       Score
		contrib []Contribution
	}
	all := map[string]*acc{}
	add := func(typ, key, display string, elevated bool, in Input, pts float64) {
		id := typ + "\x00" + key
		a, ok := all[id]
		if !ok {
			a = &acc{s: Score{Type: typ, Entity: key, Display: display}}
			all[id] = a
		}
		// Nazwa do pokazania: najdłuższa (pełna nazwa komputera z domeną).
		if len(display) > len(a.s.Display) || (len(display) == len(a.s.Display) && display < a.s.Display) {
			a.s.Display = display
		}
		if elevated {
			pts *= cfg.Multiplier
			a.s.Elevated = true
		}
		a.s.Score += pts
		a.s.Alerts++
		if in.LastSeen.After(a.s.LastAlertAt) {
			a.s.LastAlertAt = in.LastSeen
		}
		a.contrib = append(a.contrib, Contribution{AlertID: in.AlertID, RuleID: in.RuleID, RuleTitle: in.RuleTitle,
			Level: in.Level, LastSeen: in.LastSeen, Points: pts})
	}
	for _, in := range inputs {
		if !Counts(in) {
			continue
		}
		base := cfg.Points[in.Level]
		if base <= 0 {
			continue
		}
		age := max(now.Sub(in.LastSeen).Hours()/24, 0)
		pts := base * math.Pow(0.5, age/cfg.HalfLifeDays)
		if pts < 0.01 {
			continue
		}
		if key, display := UserKey(in.UserIdentity, in.UserName); key != "" {
			add(User, key, display, cfg.Privileged(in.UserIdentity, in.UserName), in, pts)
		}
		if key, display := HostKey(in.HostName); key != "" {
			add(Host, key, display, in.GroupID != 0 && slices.Contains(cfg.CriticalGroups, in.GroupID), in, pts)
		}
	}
	out := make([]Score, 0, len(all))
	for _, a := range all {
		s := a.s
		s.Score = math.Round(s.Score*10) / 10
		s.Level = cfg.LevelOf(s.Score)
		sort.Slice(a.contrib, func(i, j int) bool { return a.contrib[i].Points > a.contrib[j].Points })
		if len(a.contrib) > MaxTop {
			a.contrib = a.contrib[:MaxTop]
		}
		for i := range a.contrib {
			a.contrib[i].Points = math.Round(a.contrib[i].Points*10) / 10
		}
		s.Top = a.contrib
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Type+out[i].Entity < out[j].Type+out[j].Entity
	})
	return out
}
