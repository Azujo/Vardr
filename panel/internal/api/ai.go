// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"siem/internal/lang"
	"siem/panel/internal/api/store"
)

// Dostęp AI przez MCP (wersja 1.4). Serwer MCP (vardr-mcp) działa na
// komputerze analityka i woła API tokenem rodzaju „ai”. Model widzi
// wyłącznie to, co zwrócą narzędzia, więc wszystkie ograniczenia są tutaj,
// po stronie serwera, i obowiązują każde zapytanie tokenem AI – także
// wysłane z pominięciem vardr-mcp:
//
//   - profil uprawnień tokenu (jak każdy token);
//   - polityka AI z panelu: główny wyłącznik, włączone grupy narzędzi
//     (każda to lista tras tylko do odczytu), zakres danych (okres, liczba
//     wierszy, wykluczone źródła) i maskowanie danych osobowych (aimask.go);
//   - ostrzeżenia (RODO, halucynacje, prompt injection) potwierdzone przez
//     administratora przy włączeniu.

// AIToolGroup to grupa narzędzi MCP z trasami API, z których korzysta.
type AIToolGroup struct {
	ID string `json:"id"`
	// Default: włączona w nowej polityce.
	Default bool `json:"default"`
	// Sensitive: dane szczególnie wrażliwe (incydenty, profilowanie, surowe
	// zdarzenia) – panel pokazuje ostrzeżenie.
	Sensitive bool     `json:"sensitive"`
	Routes    []string `json:"routes"`
}

// AIToolGroups: grupy narzędzi (kolejność – panel i vardr-mcp).
var AIToolGroups = []AIToolGroup{
	{ID: "events", Default: true, Routes: []string{"GET /api/v1/events", "GET /api/v1/events/fields"}},
	{ID: "histogram", Default: true, Routes: []string{"GET /api/v1/events/histogram"}},
	{ID: "alerts", Default: true, Routes: []string{"GET /api/v1/alerts", "GET /api/v1/alerts/summary", "GET /api/v1/alerts/{id}"}},
	{ID: "rules", Default: true, Routes: []string{"GET /api/v1/rules", "GET /api/v1/attack/coverage"}},
	{ID: "system", Default: true, Routes: []string{"GET /api/v1/system", "GET /api/v1/agents"}},
	{ID: "raw_events", Sensitive: true, Routes: []string{"GET /api/v1/events/{id}"}},
	{ID: "incidents", Sensitive: true, Routes: []string{"GET /api/v1/incidents", "GET /api/v1/incidents/{id}"}},
	{ID: "risk", Sensitive: true, Routes: []string{"GET /api/v1/risk", "GET /api/v1/risk/{type}/{entity}"}},
}

// aiAlways: trasy dostępne dla tokenu AI przy włączonej polityce
// (vardr-mcp sprawdza nimi siebie i politykę).
var aiAlways = []string{"GET /api/v1/api-tokens/self", "GET /api/v1/ai/policy", mcpPattern}

// AIDisclaimerVersion: wersja ostrzeżeń – zmiana treści wymaga ponownego
// potwierdzenia przez administratora.
const AIDisclaimerVersion = 1

// AIMask: co maskować (pseudonimy) w odpowiedziach dla AI.
type AIMask struct {
	Users  bool `json:"users"`
	Hosts  bool `json:"hosts"`
	IPs    bool `json:"ips"`
	Emails bool `json:"emails"`
}

func (m AIMask) any() bool { return m.Users || m.Hosts || m.IPs || m.Emails }

// AIPolicy to polityka dostępu AI (panel_settings, klucz ai_policy).
type AIPolicy struct {
	Enabled bool            `json:"enabled"`
	Tools   map[string]bool `json:"tools"`
	// MaxRangeHours: najdłuższy okres zapytania o zdarzenia; MaxRows –
	// najwięcej zdarzeń w odpowiedzi.
	MaxRangeHours int `json:"max_range_hours"`
	MaxRows       int `json:"max_rows"`
	// ExcludedDatasets: źródła niedostępne dla AI (np. systemy kadrowe).
	ExcludedDatasets []string `json:"excluded_datasets"`
	Mask             AIMask   `json:"mask"`
	// Potwierdzenie ostrzeżeń przy włączeniu (kto, kiedy, która wersja).
	AckVersion int        `json:"ack_version"`
	AckBy      string     `json:"ack_by,omitempty"`
	AckAt      *time.Time `json:"ack_at,omitempty"`
}

const (
	aiPolicyKey        = "ai_policy"
	aiDefaultRangeH    = 24 * 7
	aiMaxRangeH        = 24 * 31
	aiDefaultRows      = 100
	aiMaxRows          = 200
	aiPolicyCacheTTL   = 15 * time.Second
	aiMaxExcluded      = 100
	aiDatasetMaxLength = 100
)

// DefaultAIPolicy: wyłączona, domyślne grupy narzędzi, bez maskowania
// (decyzja projektu: maskowanie włącza administrator).
func DefaultAIPolicy() AIPolicy {
	p := AIPolicy{Tools: map[string]bool{}, MaxRangeHours: aiDefaultRangeH, MaxRows: aiDefaultRows}
	for _, g := range AIToolGroups {
		p.Tools[g.ID] = g.Default
	}
	return p
}

func (p AIPolicy) normalize() AIPolicy {
	d := DefaultAIPolicy()
	if p.Tools == nil {
		p.Tools = map[string]bool{}
	}
	for _, g := range AIToolGroups {
		if _, ok := p.Tools[g.ID]; !ok {
			p.Tools[g.ID] = d.Tools[g.ID]
		}
	}
	if p.MaxRangeHours <= 0 {
		p.MaxRangeHours = d.MaxRangeHours
	}
	if p.MaxRows <= 0 {
		p.MaxRows = d.MaxRows
	}
	return p
}

func (p AIPolicy) validate() error {
	for id := range p.Tools {
		if !slices.ContainsFunc(AIToolGroups, func(g AIToolGroup) bool { return g.ID == id }) {
			return lang.Errorf("nieznana grupa narzędzi %q", "unknown tool group %q", id)
		}
	}
	if p.MaxRangeHours < 1 || p.MaxRangeHours > aiMaxRangeH {
		return lang.Errorf("okres zapytania: od 1 do 744 godzin (31 dni)", "query period: 1 to 744 hours (31 days)")
	}
	if p.MaxRows < 1 || p.MaxRows > aiMaxRows {
		return lang.Errorf("liczba wierszy: od 1 do 200", "number of rows: 1 to 200")
	}
	if len(p.ExcludedDatasets) > aiMaxExcluded {
		return lang.Errorf("za dużo wykluczonych źródeł", "too many excluded sources")
	}
	for _, d := range p.ExcludedDatasets {
		if d == "" || len(d) > aiDatasetMaxLength {
			return lang.Errorf("niepoprawne źródło %q", "invalid source %q", d)
		}
	}
	return nil
}

// allows: trasa (wzorzec ServeMux) dostępna dla tokenu AI.
func (p AIPolicy) allows(pattern string) bool {
	if slices.Contains(aiAlways, pattern) {
		return true
	}
	for _, g := range AIToolGroups {
		if p.Tools[g.ID] && slices.Contains(g.Routes, pattern) {
			return true
		}
	}
	return false
}

type aiPolicyCache struct {
	mu  sync.Mutex
	at  time.Time
	pol *AIPolicy
}

// aiPolicy: polityka AI (z pamięci podręcznej 15 s; zmiana w panelu ją
// czyści). Bez ustawień w bazie – domyślna, czyli wyłączona.
func (s *Server) aiPolicy(ctx context.Context) (AIPolicy, error) {
	c := &s.aiCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pol != nil && s.now().Sub(c.at) < aiPolicyCacheTTL {
		return *c.pol, nil
	}
	p := DefaultAIPolicy()
	if s.Settings != nil {
		raw, err := s.Settings.Setting(ctx, aiPolicyKey)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return p, err
		default:
			if err := json.Unmarshal([]byte(raw), &p); err != nil {
				return DefaultAIPolicy(), err
			}
		}
	}
	p = p.normalize()
	c.pol, c.at = &p, s.now()
	return p, nil
}

func (s *Server) dropAIPolicyCache() {
	s.aiCache.mu.Lock()
	s.aiCache.pol = nil
	s.aiCache.mu.Unlock()
}

// aiGate: sprawdzenie polityki AI dla tokenu AI przed handlerem. Zwraca
// politykę (do limitów i maskowania) albo false, gdy odpowiedź już wysłano.
func (s *Server) aiGate(w http.ResponseWriter, r *http.Request, a authCtx) (AIPolicy, bool) {
	pol, err := s.aiPolicy(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return pol, false
	}
	if !pol.Enabled {
		s.tokenDenied(r, a, "ai:disabled")
		writeError(w, http.StatusForbidden, "ai_disabled", "dostęp AI jest wyłączony w panelu (Administracja → Dostęp AI)")
		return pol, false
	}
	if !pol.allows(r.Pattern) {
		s.tokenDenied(r, a, "ai:"+r.Pattern)
		writeError(w, http.StatusForbidden, "ai_not_allowed", "polityka AI nie pozwala na to zapytanie (narzędzie wyłączone albo zapytanie poza listą narzędzi AI)")
		return pol, false
	}
	return pol, true
}

// ---- panel: polityka, historia, pseudonimy ----

type aiToolView struct {
	AIToolGroup
	Enabled bool `json:"enabled"`
}

// aiPolicyView: polityka z opisem grup narzędzi (panel i vardr-mcp).
func (s *Server) getAIPolicy(w http.ResponseWriter, r *http.Request) {
	pol, err := s.aiPolicy(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	tools := make([]aiToolView, 0, len(AIToolGroups))
	for _, g := range AIToolGroups {
		tools = append(tools, aiToolView{AIToolGroup: g, Enabled: pol.Tools[g.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": pol, "tools": tools, "disclaimer_version": AIDisclaimerVersion,
		"acknowledged": pol.AckVersion >= AIDisclaimerVersion, "settings": s.Settings != nil})
}

// setAIPolicy zmienia politykę AI – zawsze z hasłem; włączenie wymaga
// potwierdzenia ostrzeżeń (RODO, halucynacje, prompt injection) w bieżącej
// wersji. Zmiana trafia do audytu z poprzednią polityką.
func (s *Server) setAIPolicy(w http.ResponseWriter, r *http.Request) {
	if s.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings_disabled", "ustawienia panelu niedostępne w tej konfiguracji")
		return
	}
	a := current(r)
	var req struct {
		Policy      AIPolicy `json:"policy"`
		Acknowledge bool     `json:"acknowledge"`
		Password    string   `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	pol := req.Policy.normalize()
	var ds []string
	for _, d := range pol.ExcludedDatasets {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" && !slices.Contains(ds, d) {
			ds = append(ds, d)
		}
	}
	pol.ExcludedDatasets = ds
	if err := pol.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_ai_policy", err)
		return
	}
	prev, err := s.aiPolicy(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	// Potwierdzenie ostrzeżeń: przy włączeniu, gdy nie ma aktualnego.
	pol.AckVersion, pol.AckBy, pol.AckAt = prev.AckVersion, prev.AckBy, prev.AckAt
	if pol.Enabled && prev.AckVersion < AIDisclaimerVersion {
		if !req.Acknowledge {
			writeError(w, http.StatusBadRequest, "ai_ack_required", "włączenie dostępu AI wymaga potwierdzenia ostrzeżeń (RODO, halucynacje, prompt injection)")
			return
		}
		now := s.now()
		pol.AckVersion, pol.AckBy, pol.AckAt = AIDisclaimerVersion, a.user.Username, &now
	}
	if !s.reauth(w, r, req.Password, "ai_policy") {
		return
	}
	raw, err := json.Marshal(pol)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.Settings.SetSetting(r.Context(), aiPolicyKey, string(raw), a.user.Username, s.now()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.dropAIPolicyCache()
	s.audit(r, &a.user, "ai_policy_changed", "ai", map[string]any{"policy": pol, "previous": prev,
		"acknowledged": req.Acknowledge && pol.AckBy == a.user.Username})
	writeJSON(w, http.StatusOK, map[string]any{"policy": pol})
}

// AIStore to historia zapytań tokenów AI i pseudonimy (implementuje store.PG).
type AIStore interface {
	APIRequestsByKind(ctx context.Context, kind string, limit int, beforeID int64) ([]store.KindRequest, error)
	SavePseudonyms(ctx context.Context, ps []store.Pseudonym, now time.Time) error
	PseudonymOf(ctx context.Context, pseudonym string) (store.Pseudonym, error)
}

func (s *Server) aiEnabledStore(w http.ResponseWriter) bool {
	if s.AI == nil {
		writeError(w, http.StatusServiceUnavailable, "ai_unavailable", "dostęp AI niedostępny w tej konfiguracji")
		return false
	}
	return true
}

// listAIRequests: zapytania wszystkich tokenów AI (najnowsze pierwsze).
func (s *Server) listAIRequests(w http.ResponseWriter, r *http.Request) {
	if !s.aiEnabledStore(w) {
		return
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	list, err := s.AI.APIRequestsByKind(r.Context(), store.TokenAI, 100, before)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": list})
}

// revealPseudonym: wartość pseudonimu (uprawnienie „odkrywanie”, audyt).
func (s *Server) revealPseudonym(w http.ResponseWriter, r *http.Request) {
	if !s.aiEnabledStore(w) {
		return
	}
	a := current(r)
	var req struct {
		Pseudonym string `json:"pseudonym"`
		Reason    string `json:"reason"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Pseudonym = strings.ToUpper(strings.TrimSpace(req.Pseudonym))
	req.Reason = strings.TrimSpace(req.Reason)
	if !pseudonymPattern.MatchString(req.Pseudonym) {
		writeError(w, http.StatusBadRequest, "bad_pseudonym", "pseudonim ma postać np. USER-7f3a12bc, HOST-…, IP-…, EMAIL-…")
		return
	}
	if len([]rune(req.Reason)) < 3 || len(req.Reason) > 500 {
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód odkrycia pseudonimu (np. numer alertu lub incydentu)")
		return
	}
	p, err := s.AI.PseudonymOf(r.Context(), req.Pseudonym)
	if errors.Is(err, store.ErrNotFound) {
		s.audit(r, &a.user, "ai_pseudonym_revealed", req.Pseudonym, map[string]any{"reason": req.Reason, "found": false})
		writeError(w, http.StatusNotFound, "not_found", "nieznany pseudonim")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "ai_pseudonym_revealed", req.Pseudonym, map[string]any{"reason": req.Reason, "kind": p.Kind, "found": true})
	writeJSON(w, http.StatusOK, map[string]any{"pseudonym": p})
}

// downloadMCP: program vardr-mcp.exe (serwer MCP dla klienta AI na
// komputerze analityka) – jak instalator agenta, z dysku serwera.
func (s *Server) downloadMCP(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	path := s.MCPExe
	if path == "" {
		path = "/agent-dist/vardr-mcp.exe"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeError(w, http.StatusNotFound, "mcp_missing", "brak programu vardr-mcp.exe na serwerze (deploy.sh tools albo paczka instalacyjna)")
		return
	}
	s.audit(r, &a.user, "ai_mcp_downloaded", "vardr-mcp.exe", nil)
	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", `attachment; filename="vardr-mcp.exe"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// downloadCA: certyfikat CA serwera (VARDR_CA_FILE dla vardr-mcp) – jawny,
// ten sam co w paczkach agentów.
func (s *Server) downloadCA(w http.ResponseWriter, r *http.Request) {
	if s.Enroll == nil || s.Enroll.RootCA == "" {
		writeError(w, http.StatusNotFound, "ca_missing", "certyfikat CA serwera niedostępny w tej konfiguracji")
		return
	}
	data, err := os.ReadFile(s.Enroll.RootCA)
	if err != nil {
		writeError(w, http.StatusNotFound, "ca_missing", "certyfikat CA serwera niedostępny w tej konfiguracji")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="vardr-ca.crt"`)
	_, _ = w.Write(data)
}
