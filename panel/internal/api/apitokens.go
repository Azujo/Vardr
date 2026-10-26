// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
	"siem/panel/internal/perm"
)

// APITokenStore to tokeny API (implementuje store.PG). Opcjonalne: bez
// niego API przyjmuje tylko sesje panelu.
type APITokenStore interface {
	CreateAPIToken(ctx context.Context, t store.APIToken) (store.APIToken, error)
	ListAPITokens(ctx context.Context, now time.Time) ([]store.APIToken, error)
	APITokenByHash(ctx context.Context, hash string, now time.Time) (store.APIToken, error)
	TouchAPIToken(ctx context.Context, id int64, at time.Time, ip string) error
	RevokeAPIToken(ctx context.Context, id int64, by string, now time.Time) (store.APIToken, error)
	RecordAPIRequests(ctx context.Context, reqs []store.APIRequest) error
	APIRequests(ctx context.Context, tokenID int64, limit int, beforeID int64) ([]store.APIRequest, error)
	APIRequestCounts(ctx context.Context, since time.Time) (map[int64]int, error)
}

const (
	// apiTokenPrefix: początek każdego tokenu – łatwo go rozpoznać w kodzie
	// i w skanerach sekretów (np. GitHub secret scanning).
	apiTokenPrefix = "vardr_"
	// Ważność tokenu: domyślnie 90 dni, najwyżej rok – token bez końca
	// ważności zostaje w zapomnianych skryptach.
	defaultTokenDays = 90
	maxTokenDays     = 365
	// defaultTokenRate: limit zapytań jednego tokenu na minutę.
	defaultTokenRate = 600
	// actorPrefix: aktor w audycie i polach „kto” (alerty, incydenty) –
	// loginy kont nie mogą zawierać dwukropka, więc nie da się go podrobić.
	actorPrefix = "api:"
)

// tokenPerms: uprawnienia tokenu – profilu, ale bez zarządzania kontami
// (users najwyżej do odczytu). Token nie może zakładać kont, zmieniać
// profili ani tworzyć kolejnych tokenów – przejęty token nie daje trwałego
// przyczółka w panelu.
func tokenPerms(p perm.Set) perm.Set {
	out := perm.Set{}
	for mod, level := range p {
		out[mod] = level
	}
	if p.Has("users", "write") {
		out["users"] = "read"
	}
	return out
}

// tokenAuthed obsługuje żądanie z nagłówkiem Authorization (token API).
// Bez CSRF – token nie jest wysyłany przez przeglądarkę automatycznie.
func (s *Server) tokenAuthed(w http.ResponseWriter, r *http.Request, req need, flags int, header string, h http.HandlerFunc) {
	ip := clientIP(r)
	token, ok := strings.CutPrefix(header, "Bearer ")
	token = strings.TrimSpace(token)
	if !ok || !strings.HasPrefix(token, apiTokenPrefix) || s.APITokens == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="vardr"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "nieprawidłowy, wygasły lub unieważniony token API")
		return
	}
	// Zgadywanie tokenu (256 bitów) jest beznadziejne, ale limit na adres
	// chroni bazę przed zalewem błędnych prób.
	if !s.allow("token-ip:"+ip, 600, 100) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "zbyt wiele zapytań – odczekaj minutę")
		return
	}
	now := s.now()
	t, err := s.APITokens.APITokenByHash(r.Context(), auth.TokenID(token), now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if s.allow("token-bad:"+ip, 10, 10) { // log bez zalewu
			s.Log.Warn("invalid API token", "ip", ip, "path", r.URL.Path)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="vardr", error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "nieprawidłowy, wygasły lub unieważniony token API")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	rate := s.TokenRatePerMin
	if rate <= 0 {
		rate = defaultTokenRate
	}
	if !s.allow("token:"+strconv.FormatInt(t.ID, 10), float64(rate), float64(max(rate/6, 10))) {
		// Odmowy 429 nie trafiają do historii – zalew zapytań zalałby też bazę.
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "przekroczony limit zapytań tokenu – zwolnij")
		return
	}
	// Od tej chwili każde zapytanie (także odmowa uprawnień) trafia do
	// historii tokenu i do logu.
	sw := &statusWriter{ResponseWriter: w}
	w = sw
	started := time.Now()
	defer func() { s.logTokenRequest(r, &t, sw.status, time.Since(started), ip) }()

	user := store.User{Username: actorPrefix + t.Name, DisplayName: t.Name, Role: t.Profile, Source: "api"}
	a := authCtx{user: user, token: &t}
	if req == loggedIn && flags&allowToken == 0 {
		s.tokenDenied(r, a, "session_only")
		writeError(w, http.StatusForbidden, "token_not_allowed", "ta operacja jest dostępna tylko po zalogowaniu w panelu")
		return
	}
	a.perms = tokenPerms(s.permsOf(r.Context(), t.Profile))
	if req != loggedIn && !a.perms.Has(req.mod, req.level) {
		s.tokenDenied(r, a, req.mod+":"+req.level)
		writeError(w, http.StatusForbidden, "forbidden", "brak uprawnień do tej operacji")
		return
	}
	// Token AI: polityka AI (wyłącznik, narzędzia) przed handlerem.
	if t.Kind == store.TokenAI {
		pol, ok := s.aiGate(w, r, a)
		if !ok {
			return
		}
		a.ai = &pol
	}
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > time.Minute || t.LastUsedIP != ip {
		if err := s.APITokens.TouchAPIToken(context.WithoutCancel(r.Context()), t.ID, now, ip); err != nil {
			s.Log.Warn("recording API token use failed", "err", err)
		}
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, a))
	// Endpoint MCP nie jest maskowany drugi raz: zwraca wyniki wewnętrznych
	// zapytań, a te są już zamaskowane.
	if a.ai != nil && a.ai.Mask.any() && r.Pattern != mcpPattern {
		s.serveMasked(w, r, *a.ai, h)
		return
	}
	h(w, r)
}

// tokenDenied zapisuje w audycie odmowę dla tokenu: program próbuje czegoś
// spoza swojego profilu – błąd integracji albo nadużycie przejętego tokenu.
func (s *Server) tokenDenied(r *http.Request, a authCtx, need string) {
	key := "token-denied:" + strconv.FormatInt(a.token.ID, 10)
	if !s.allow(key, 6, 20) { // seria odmów – wpisy co kilka, nie każda
		return
	}
	s.audit(r.WithContext(context.WithValue(r.Context(), ctxKey{}, a)), &a.user, "api_token_denied", a.token.Name,
		map[string]any{"method": r.Method, "path": r.URL.Path, "need": need})
}

// ---- zarządzanie tokenami (panel, administrator) ----

func (s *Server) listAPITokens(w http.ResponseWriter, r *http.Request) {
	if s.APITokens == nil {
		writeJSON(w, http.StatusOK, map[string]any{"tokens": []store.APIToken{}, "enabled": false})
		return
	}
	list, err := s.APITokens.ListAPITokens(r.Context(), s.now())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if list == nil {
		list = []store.APIToken{}
	}
	counts, err := s.APITokens.APIRequestCounts(r.Context(), s.now().Add(-24*time.Hour))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": list, "enabled": true, "requests_24h": counts,
		"default_days": defaultTokenDays, "max_days": maxTokenDays, "log_days": s.tokenLogDays()})
}

// listAPITokenRequests: historia zapytań tokenu (najnowsze pierwsze, po 100).
func (s *Server) listAPITokenRequests(w http.ResponseWriter, r *http.Request) {
	if s.APITokens == nil {
		writeError(w, http.StatusServiceUnavailable, "tokens_disabled", "tokeny API niedostępne w tej konfiguracji")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator")
		return
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	list, err := s.APITokens.APIRequests(r.Context(), id, 100, before)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": list})
}

// createAPIToken tworzy token – zawsze z hasłem (nowe poświadczenie
// z uprawnieniami profilu). Pełny token jest tylko w tej odpowiedzi.
func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	if s.APITokens == nil {
		writeError(w, http.StatusServiceUnavailable, "tokens_disabled", "tokeny API niedostępne w tej konfiguracji")
		return
	}
	a := current(r)
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Profile     string `json:"profile"`
		Days        int    `json:"days"`
		Password    string `json:"password"`
		// Kind: integration (domyślnie) albo ai – z potwierdzeniem ostrzeżeń.
		Kind        string `json:"kind"`
		Acknowledge bool   `json:"acknowledge"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name, req.Description = strings.TrimSpace(req.Name), strings.TrimSpace(req.Description)
	if req.Days == 0 {
		req.Days = defaultTokenDays
	}
	switch {
	case !usernamePattern.MatchString(req.Name):
		writeError(w, http.StatusBadRequest, "bad_token_name", "nazwa tokenu: 2–64 znaki, litery, cyfry, kropka, myślnik, podkreślenie")
		return
	case len(req.Description) > 300:
		writeError(w, http.StatusBadRequest, "bad_description", "opis jest za długi")
		return
	case req.Days < 1 || req.Days > maxTokenDays:
		writeError(w, http.StatusBadRequest, "bad_token_days", "ważność tokenu: od 1 do 365 dni")
		return
	case !s.profileExists(r.Context(), req.Profile):
		writeError(w, http.StatusBadRequest, "bad_role", "nie ma takiego profilu uprawnień")
		return
	case req.Kind != "" && req.Kind != store.TokenIntegration && req.Kind != store.TokenAI:
		writeError(w, http.StatusBadRequest, "bad_token_kind", "rodzaj tokenu: integration albo ai")
		return
	case req.Kind == store.TokenAI && !req.Acknowledge:
		writeError(w, http.StatusBadRequest, "ai_ack_required", "token AI wymaga potwierdzenia ostrzeżeń (RODO, halucynacje, prompt injection)")
		return
	}
	if !s.reauth(w, r, req.Password, "api_token_create") {
		return
	}
	now := s.now()
	token := apiTokenPrefix + auth.NewToken()
	t, err := s.APITokens.CreateAPIToken(r.Context(), store.APIToken{Name: req.Name, Description: req.Description,
		TokenHash: auth.TokenID(token), Prefix: token[:len(apiTokenPrefix)+6], Profile: req.Profile,
		CreatedBy: a.user.Username, CreatedAt: now, ExpiresAt: now.Add(time.Duration(req.Days) * 24 * time.Hour), Kind: req.Kind})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "token_name_taken", "aktywny token o tej nazwie już istnieje")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	details := map[string]any{"token_id": t.ID, "profile": t.Profile, "expires_at": t.ExpiresAt, "prefix": t.Prefix, "kind": t.Kind}
	if t.Kind == store.TokenAI {
		details["acknowledged_disclaimer"] = AIDisclaimerVersion
	}
	s.audit(r, &a.user, "api_token_created", t.Name, details)
	writeJSON(w, http.StatusCreated, map[string]any{"token": t, "secret": token})
}

func (s *Server) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	if s.APITokens == nil {
		writeError(w, http.StatusServiceUnavailable, "tokens_disabled", "tokeny API niedostępne w tej konfiguracji")
		return
	}
	a := current(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator")
		return
	}
	t, err := s.APITokens.RevokeAPIToken(r.Context(), id, a.user.Username, s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego aktywnego tokenu")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "api_token_revoked", t.Name, map[string]any{"token_id": t.ID})
	writeJSON(w, http.StatusOK, map[string]any{"token": t})
}

// tokenSelf: opis tokenu, którym program się przedstawia (sprawdzenie
// konfiguracji integracji: profil, uprawnienia, koniec ważności).
func (s *Server) tokenSelf(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	if a.token == nil {
		writeError(w, http.StatusBadRequest, "not_a_token", "to zapytanie jest dla programów z tokenem API")
		return
	}
	out := map[string]any{"name": a.token.Name, "actor": a.user.Username, "profile": a.token.Profile,
		"permissions": a.perms, "expires_at": a.token.ExpiresAt, "kind": a.token.Kind}
	if a.ai != nil {
		out["masking"] = a.ai.Mask
	}
	writeJSON(w, http.StatusOK, out)
}
