// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
	"siem/panel/internal/oidc"
)

// Logowanie przez Entra ID – OIDC (wersja 1.6.1). Przycisk na stronie
// logowania → dostawca (hasło, MFA, dostęp warunkowy) → powrót z kodem →
// token ID sprawdzony w pakiecie oidc → profil z grupy → sesja panelu.
// Konta SSO nie mają hasła w panelu: operacje chronione hasłem potwierdzają
// ponownym logowaniem u dostawcy w okienku (reauth_at w sesji, 5 minut).

// OIDCStore to konta dostawcy tożsamości (implementuje store.PG).
type OIDCStore interface {
	UpsertOIDCUser(ctx context.Context, u store.User) (store.User, error)
	UserByExternalID(ctx context.Context, id string) (store.User, error)
	SetSessionReauth(ctx context.Context, id string, at time.Time) error
}

const (
	oidcConfigKey   = "oidc_config"
	oidcSecretUsage = "oidc-client-secret"
	oidcStateCookie = "vardr_oidc"
	oidcCookiePath  = "/api/v1/auth/oidc"
	oidcPendingTTL  = 10 * time.Minute
	oidcMaxPending  = 1000
	// ssoReauthFor: jak długo potwierdzenie u dostawcy zastępuje hasło.
	ssoReauthFor = 5 * time.Minute
)

type oidcSaved struct {
	oidc.Config
	ClientSecretEnc []byte `json:"client_secret_enc,omitempty"`
}

type oidcPending struct {
	nonce, verifier string
	sessionID       string // ponowne uwierzytelnienie: sesja, której dotyczy
	userID          int64
	expires         time.Time
}

type oidcState struct {
	mu       sync.Mutex
	at       time.Time
	cfg      *oidc.Config
	provider oidc.Provider
	pending  map[string]oidcPending
}

func (s *Server) oidcAvailable() bool { return s.OIDC != nil && s.mfaEnabled() }

// oidcConfig: zapisane ustawienia (z odszyfrowanym sekretem); pusty – brak.
func (s *Server) oidcConfig(ctx context.Context) (*oidc.Config, error) {
	if !s.oidcAvailable() {
		return nil, nil
	}
	st := &s.sso
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.cfg != nil && s.now().Sub(st.at) < 30*time.Second {
		return st.cfg, nil
	}
	raw, err := s.MFA.Setting(ctx, oidcConfigKey)
	if errors.Is(err, store.ErrNotFound) {
		st.cfg, st.at = &oidc.Config{}, s.now()
		return st.cfg, nil
	}
	if err != nil {
		return nil, err
	}
	var saved oidcSaved
	if err := json.Unmarshal([]byte(raw), &saved); err != nil {
		return nil, err
	}
	cfg := saved.Config
	if len(saved.ClientSecretEnc) > 0 {
		sec, err := auth.OpenData(s.MFAKey, saved.ClientSecretEnc, oidcSecretUsage)
		if err != nil {
			return nil, errors.New("the SSO client secret cannot be read (MFA key changed?) – save it again")
		}
		cfg.ClientSecret = string(sec)
	}
	st.cfg, st.at = &cfg, s.now()
	return st.cfg, nil
}

// oidcActive: włączone logowanie SSO (nil – wyłączone albo błąd odczytu).
func (s *Server) oidcActive(ctx context.Context) *oidc.Config {
	cfg, err := s.oidcConfig(ctx)
	if err != nil {
		s.Log.Warn("ustawienia logowania SSO nieczytelne", "err", err)
		return nil
	}
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	return cfg
}

func (s *Server) dropOIDCCache() {
	s.sso.mu.Lock()
	s.sso.cfg = nil
	s.sso.mu.Unlock()
}

func (s *Server) putPending(state string, p oidcPending) bool {
	st := &s.sso
	st.mu.Lock()
	defer st.mu.Unlock()
	now := s.now()
	if st.pending == nil {
		st.pending = map[string]oidcPending{}
	}
	for k, v := range st.pending {
		if now.After(v.expires) {
			delete(st.pending, k)
		}
	}
	if len(st.pending) >= oidcMaxPending {
		return false
	}
	st.pending[state] = p
	return true
}

func (s *Server) takePending(state string) (oidcPending, bool) {
	st := &s.sso
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.pending[state]
	delete(st.pending, state)
	return p, ok && s.now().Before(p.expires)
}

// ssoRedirect: przejście na stronę panelu przez dokument HTML (meta refresh),
// nie 302 – nawigacja zaczęta u dostawcy jest międzywitrynowa, a ciasteczko
// sesji ma SameSite=Strict; strona panelu wczytana z panelu je dostanie.
func ssoRedirect(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	p := html.EscapeString(path)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=` + p +
		`"><title>Vardr</title><a href="` + p + `">Vardr</a>`))
}

// oidcInfo: przycisk na stronie logowania (bez logowania).
func (s *Server) oidcInfo(w http.ResponseWriter, r *http.Request) {
	cfg := s.oidcActive(r.Context())
	if cfg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	label := cfg.ButtonLabel
	if label == "" {
		label = "Microsoft Entra ID"
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "label": label})
}

// oidcStart: przekierowanie do dostawcy. reauth=1 – potwierdzenie tożsamości
// zalogowanego konta SSO (okienko), bez nowej sesji.
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reauth := r.URL.Query().Get("reauth") == "1"
	fail := func(code string) {
		if reauth {
			ssoRedirect(w, "/sso/done?result=error&code="+url.QueryEscape(code))
		} else {
			ssoRedirect(w, "/login?sso_error="+url.QueryEscape(code))
		}
	}
	if !s.allow("oidc:"+clientIP(r), 20, 10) {
		fail("rate_limited")
		return
	}
	cfg := s.oidcActive(ctx)
	if cfg == nil {
		fail("disabled")
		return
	}
	p := oidcPending{expires: s.now().Add(oidcPendingTTL)}
	hint := ""
	if reauth {
		c, err := r.Cookie(cookieName)
		if err != nil {
			fail("unauthenticated")
			return
		}
		sess, user, err := s.Store.SessionWithUser(ctx, auth.TokenID(c.Value), s.now())
		if err != nil || user.Source != store.SourceOIDC || user.Disabled {
			fail("unauthenticated")
			return
		}
		p.sessionID, p.userID, hint = sess.ID, user.ID, user.Username
	}
	state := oidc.RandomString(24)
	p.nonce = oidc.RandomString(24)
	var challenge string
	p.verifier, challenge = oidc.Challenge()
	target, err := s.sso.provider.AuthURL(ctx, cfg, state, p.nonce, challenge, reauth, hint)
	if err != nil {
		s.Log.Warn("SSO: provider configuration unavailable", "err", err)
		fail("provider_unavailable")
		return
	}
	if !s.putPending(state, p) {
		fail("rate_limited")
		return
	}
	// Ciasteczko wiąże powrót od dostawcy z tą przeglądarką (Lax – powrót
	// to nawigacja z innej witryny).
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: state, Path: oidcCookiePath, MaxAge: int(oidcPendingTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

// oidcCallback: powrót od dostawcy – kod, sprawdzenie tokenu, konto, sesja.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: oidcCookiePath, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	state := q.Get("state")
	c, err := r.Cookie(oidcStateCookie)
	if state == "" || err != nil || c.Value != state {
		s.audit(r, nil, "login_failed", "", map[string]any{"reason": "sso_state", "source": "oidc"})
		ssoRedirect(w, "/login?sso_error=state")
		return
	}
	p, ok := s.takePending(state)
	if !ok {
		s.audit(r, nil, "login_failed", "", map[string]any{"reason": "sso_state_expired", "source": "oidc"})
		ssoRedirect(w, "/login?sso_error=state")
		return
	}
	reauth := p.sessionID != ""
	fail := func(code, login string, details map[string]any) {
		details["source"] = "oidc"
		if reauth {
			details["operation"] = "sso"
			s.audit(r, nil, "reauth_failed", login, details)
			ssoRedirect(w, "/sso/done?result=error&code="+url.QueryEscape(code))
			return
		}
		s.audit(r, nil, "login_failed", login, details)
		ssoRedirect(w, "/login?sso_error="+url.QueryEscape(code))
	}
	cfg := s.oidcActive(ctx)
	if cfg == nil {
		fail("disabled", "", map[string]any{"reason": "sso_disabled"})
		return
	}
	if e := q.Get("error"); e != "" {
		fail("provider_error", "", map[string]any{"reason": "sso_provider_error", "error": truncate(e, 64),
			"description": truncate(q.Get("error_description"), 300)})
		return
	}
	xctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	claims, err := s.sso.provider.Exchange(xctx, cfg, q.Get("code"), p.verifier, p.nonce)
	if err != nil {
		s.Log.Warn("SSO: code exchange or ID token check failed", "err", err)
		fail("token", "", map[string]any{"reason": "sso_token", "error": truncate(err.Error(), 300)})
		return
	}
	extID := "oidc:" + claims.ID()
	login := claims.Login()

	if reauth {
		user, err := s.Store.UserByID(ctx, p.userID)
		if err != nil || user.ExternalID != extID {
			fail("other_account", login, map[string]any{"reason": "sso_other_account"})
			return
		}
		if err := s.OIDC.SetSessionReauth(ctx, p.sessionID, s.now()); err != nil {
			s.internalError(w, r, err)
			return
		}
		s.audit(r, &user, "sso_reauth", user.Username, map[string]any{"mfa": claims.MFA()})
		ssoRedirect(w, "/sso/done?result=ok")
		return
	}

	if claims.Overage {
		fail("groups_overage", login, map[string]any{"reason": "sso_groups_overage"})
		return
	}
	existing, exErr := s.OIDC.UserByExternalID(ctx, extID)
	if exErr == nil && existing.Disabled {
		fail("disabled_account", login, map[string]any{"reason": "disabled"})
		return
	}
	m, ok := cfg.ProfileFor(claims.Groups)
	if !ok || !s.profileExists(ctx, m.Profile) {
		fail("no_access", login, map[string]any{"reason": "sso_no_group", "groups": len(claims.Groups)})
		return
	}
	display := claims.Name
	if display == "" {
		display = login
	}
	user, err := s.OIDC.UpsertOIDCUser(ctx, store.User{Username: login, DisplayName: display, Role: m.Profile, ExternalID: extID})
	if errors.Is(err, store.ErrConflict) {
		fail("username_taken", login, map[string]any{"reason": "sso_username_taken"})
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	// Drugi składnik: konta SSO potwierdzają go u dostawcy (dostęp
	// warunkowy w Entra ID); polityka MFA panelu wymaga go w tokenie (amr).
	if s.mfaEnabled() && s.mfaRequired(ctx, user) && !claims.MFA() {
		fail("no_mfa", login, map[string]any{"reason": "sso_no_mfa"})
		return
	}
	if exErr != nil {
		s.audit(r, &user, "user_created", user.Username, map[string]any{"role": user.Role, "source": "oidc", "group": m.Name})
	} else if existing.Role != user.Role {
		s.audit(r, &user, "sso_profile_changed", user.Username, map[string]any{"from": existing.Role, "to": user.Role, "group": m.Name})
	}
	if _, err := s.startSession(w, r, user, claims.MFA()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &user, "login", user.Username, map[string]any{"source": "oidc", "mfa": claims.MFA(), "group": m.Name})
	ssoRedirect(w, "/")
}

// ssoReauthOK: konto SSO potwierdziło tożsamość u dostawcy w ostatnich minutach.
func (s *Server) ssoReauthOK(a authCtx) bool {
	at := a.session.ReauthAt
	return at != nil && s.now().Sub(*at) < ssoReauthFor && !at.After(s.now().Add(time.Minute))
}

// ---- ustawienia (Administracja → Logowanie SSO) ----

func (s *Server) needOIDC(w http.ResponseWriter) bool {
	if !s.oidcAvailable() {
		writeError(w, http.StatusServiceUnavailable, "oidc_disabled",
			"logowanie SSO niedostępne – wymaga klucza szyfrującego na serwerze (certs/mfa.key)")
		return false
	}
	return true
}

func (s *Server) getOIDCSettings(w http.ResponseWriter, r *http.Request) {
	if !s.oidcAvailable() {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	cfg, err := s.oidcConfig(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	c := *cfg
	hasSecret := c.ClientSecret != ""
	c.ClientSecret = ""
	if c.Mappings == nil {
		c.Mappings = []oidc.Mapping{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "config": c, "has_secret": hasSecret})
}

type oidcDraft struct {
	Config       oidc.Config `json:"config"`
	ClientSecret string      `json:"client_secret"` // puste – zapisany (tylko przy tym samym wystawcy i aplikacji)
	Password     string      `json:"password"`
}

// draft: ustawienia z formularza; zapisany sekret tylko do tego samego
// wystawcy i aplikacji – inaczej dałoby się go wysłać na własny serwer.
func (s *Server) oidcDraft(w http.ResponseWriter, r *http.Request, d *oidcDraft) (*oidc.Config, bool) {
	c := d.Config
	c.Issuer = strings.TrimSuffix(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.RedirectURL = strings.TrimSpace(c.RedirectURL)
	c.ClientSecret = d.ClientSecret
	if c.ClientSecret == "" {
		saved, err := s.oidcConfig(r.Context())
		if err != nil {
			s.internalError(w, r, err)
			return nil, false
		}
		if saved != nil && saved.Issuer == c.Issuer && saved.ClientID == c.ClientID {
			c.ClientSecret = saved.ClientSecret
		}
	}
	return &c, true
}

// testOIDC: konfiguracja dostawcy (discovery) i klucze podpisu – bez logowania.
func (s *Server) testOIDC(w http.ResponseWriter, r *http.Request) {
	if !s.needOIDC(w) {
		return
	}
	if !s.allow("oidctest:"+current(r).user.Username, 20, 5) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "zbyt wiele prób – odczekaj chwilę")
		return
	}
	var d oidcDraft
	if !readJSON(w, r, &d) {
		return
	}
	c, ok := s.oidcDraft(w, r, &d)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var p oidc.Provider
	disc, err := p.Discover(ctx, c.Issuer)
	if err != nil {
		writeJSON(w, http.StatusOK, failed(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "authorization_endpoint": disc.AuthURL,
		"message": "konfiguracja dostawcy pobrana – zapisz ustawienia i sprawdź logowanie w oknie prywatnym"})
}

func (s *Server) saveOIDCSettings(w http.ResponseWriter, r *http.Request) {
	if !s.needOIDC(w) {
		return
	}
	a := current(r)
	var d oidcDraft
	if !readJSON(w, r, &d) {
		return
	}
	c, ok := s.oidcDraft(w, r, &d)
	if !ok {
		return
	}
	for i, m := range c.Mappings {
		if strings.TrimSpace(m.Group) == "" || !s.profileExists(r.Context(), m.Profile) {
			writeError(w, http.StatusBadRequest, "bad_mapping", "powiązanie #"+itoaInt(i+1)+": grupa bez identyfikatora albo nieznany profil")
			return
		}
	}
	if len(c.ButtonLabel) > 60 {
		writeError(w, http.StatusBadRequest, "bad_config", "napis na przycisku: najwyżej 60 znaków")
		return
	}
	if c.Enabled {
		if err := c.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_config", err)
			return
		}
	}
	if !s.reauth(w, r, d.Password, "oidc_settings") {
		return
	}
	out := oidcSaved{Config: *c}
	out.ClientSecret = ""
	if c.ClientSecret != "" {
		var err error
		if out.ClientSecretEnc, err = auth.SealData(s.MFAKey, []byte(c.ClientSecret), oidcSecretUsage); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	raw, _ := json.Marshal(out)
	if err := s.MFA.SetSetting(r.Context(), oidcConfigKey, string(raw), a.user.Username, s.now()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.dropOIDCCache()
	groups := make([]string, 0, len(c.Mappings))
	for _, m := range c.Mappings {
		groups = append(groups, m.Name+" ("+m.Group+") → "+m.Profile)
	}
	s.audit(r, &a.user, "oidc_settings_changed", "", map[string]any{"enabled": c.Enabled, "issuer": c.Issuer, "client_id": c.ClientID,
		"redirect_url": c.RedirectURL, "mappings": groups, "secret_changed": d.ClientSecret != ""})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
