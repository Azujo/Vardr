// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
	"siem/panel/internal/ldapauth"
)

// LDAPStore to konta domenowe (implementuje store.PG).
type LDAPStore interface {
	UpsertLDAPUser(ctx context.Context, u store.User) (store.User, error)
	UserByExternalID(ctx context.Context, sid string) (store.User, error)
}

const (
	ldapConfigKey   = "ldap_config"
	ldapSecretUsage = "ldap-bind-password"
	ldapSyncEvery   = 5 * time.Minute
)

// ldapSaved: ustawienia w panel_settings (hasło konta usługowego zaszyfrowane).
type ldapSaved struct {
	ldapauth.Config
	BindPasswordEnc []byte `json:"bind_password_enc,omitempty"`
}

type ldapState struct {
	mu      sync.Mutex
	at      time.Time
	cfg     *ldapauth.Config
	revoked map[string]bool // SID kont, którym synchronizacja już odebrała dostęp
}

func (s *Server) ldapAvailable() bool { return s.LDAP != nil && s.mfaEnabled() }

// ldapConfig: zapisane ustawienia (z odszyfrowanym hasłem); nil – brak.
func (s *Server) ldapConfig(ctx context.Context) (*ldapauth.Config, error) {
	if !s.ldapAvailable() {
		return nil, nil
	}
	st := &s.ldap
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.cfg != nil && s.now().Sub(st.at) < 30*time.Second {
		return st.cfg, nil
	}
	raw, err := s.MFA.Setting(ctx, ldapConfigKey)
	if errors.Is(err, store.ErrNotFound) {
		st.cfg, st.at = &ldapauth.Config{}, s.now()
		return st.cfg, nil
	}
	if err != nil {
		return nil, err
	}
	var saved ldapSaved
	if err := json.Unmarshal([]byte(raw), &saved); err != nil {
		return nil, err
	}
	cfg := saved.Config
	if len(saved.BindPasswordEnc) > 0 {
		pw, err := auth.OpenData(s.MFAKey, saved.BindPasswordEnc, ldapSecretUsage)
		if err != nil {
			return nil, errors.New("the LDAP service account password cannot be read (MFA key changed?) – save it again")
		}
		cfg.BindPassword = string(pw)
	}
	st.cfg, st.at = &cfg, s.now()
	return st.cfg, nil
}

// ldapActive: włączone logowanie domenowe (nil – wyłączone albo błąd odczytu).
func (s *Server) ldapActive(ctx context.Context) *ldapauth.Config {
	cfg, err := s.ldapConfig(ctx)
	if err != nil {
		s.Log.Warn("ustawienia logowania domenowego nieczytelne", "err", err)
		return nil
	}
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	return cfg
}

func (s *Server) dropLDAPCache() {
	s.ldap.mu.Lock()
	s.ldap.cfg = nil
	s.ldap.mu.Unlock()
}

// ldapLogin: logowanie kontem domenowym – hasło i grupy z AD, profil
// z pierwszego pasującego powiązania, konto w panelu zakładane/aktualizowane.
func (s *Server) ldapLogin(w http.ResponseWriter, r *http.Request, cfg *ldapauth.Config, login, password string) {
	ctx, now := r.Context(), s.now()
	short := strings.ToLower(ldapauth.NormalizeLogin(login))
	if at := strings.Index(short, "@"); at >= 0 {
		short = short[:at]
	}
	local, localErr := s.Store.UserByUsername(ctx, short)
	if localErr == nil && local.Source == store.SourceLDAP && local.LockedUntil != nil && local.LockedUntil.After(now) {
		s.audit(r, &local, "login_failed", local.Username, map[string]any{"reason": "locked", "source": "ldap"})
		writeError(w, http.StatusUnauthorized, "bad_credentials", badLogin)
		return
	}
	acct, err := cfg.Authenticate(ctx, login, password)
	if errors.Is(err, ldapauth.ErrBadCredentials) {
		details := map[string]any{"reason": "ldap_bad_password"}
		if localErr == nil && local.Source == store.SourceLDAP {
			if until, err := s.Store.RecordLoginFailure(ctx, local.ID, s.LockAfter, s.LockFor); err == nil && until != nil && until.After(now) {
				details["reason"] = "ldap_bad_password_locked"
			}
			s.audit(r, &local, "login_failed", local.Username, details)
		} else {
			s.audit(r, nil, "login_failed", login, details)
		}
		writeError(w, http.StatusUnauthorized, "bad_credentials", badLogin)
		return
	}
	if err != nil {
		s.Log.Error("domain sign-in – AD connection error", "err", err)
		s.audit(r, nil, "login_failed", login, map[string]any{"reason": "ldap_error", "error": err.Error()})
		writeError(w, http.StatusServiceUnavailable, "ldap_unavailable", "kontroler domeny jest niedostępny – spróbuj później albo użyj konta lokalnego")
		return
	}
	existing, exErr := s.LDAP.UserByExternalID(ctx, acct.SID)
	if exErr == nil && existing.Disabled {
		s.audit(r, &existing, "login_failed", existing.Username, map[string]any{"reason": "disabled", "source": "ldap"})
		writeError(w, http.StatusUnauthorized, "bad_credentials", badLogin)
		return
	}
	m, ok := cfg.ProfileFor(acct.GroupSIDs)
	if !ok || !s.profileExists(ctx, m.Profile) {
		s.audit(r, nil, "login_failed", acct.Login, map[string]any{"reason": "ldap_no_group", "sid": acct.SID})
		writeError(w, http.StatusForbidden, "no_access", "konto domenowe nie ma dostępu do panelu – nie należy do żadnej grupy przypisanej do profilu")
		return
	}
	display := acct.DisplayName
	if display == "" {
		display = acct.Login
	}
	user, err := s.LDAP.UpsertLDAPUser(ctx, store.User{Username: strings.ToLower(acct.Login), DisplayName: display, Role: m.Profile,
		ExternalID: acct.SID, LDAPDN: acct.DN})
	if errors.Is(err, store.ErrConflict) {
		s.audit(r, nil, "login_failed", acct.Login, map[string]any{"reason": "ldap_username_taken"})
		writeError(w, http.StatusConflict, "username_taken",
			"login konta domenowego jest zajęty przez konto lokalne panelu – administrator musi zmienić jedno z nich")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if exErr != nil {
		s.audit(r, &user, "user_created", user.Username, map[string]any{"role": user.Role, "source": "ldap", "group": m.Name})
	} else if existing.Role != user.Role {
		s.audit(r, &user, "ldap_profile_changed", user.Username, map[string]any{"from": existing.Role, "to": user.Role, "group": m.Name})
	}
	s.ldap.mu.Lock()
	delete(s.ldap.revoked, acct.SID)
	s.ldap.mu.Unlock()
	s.afterPassword(w, r, user)
}

// ldapReauth: ponowne podanie hasła konta domenowego – sprawdza AD.
func (s *Server) ldapReauth(ctx context.Context, u store.User, password string) (bool, error) {
	cfg := s.ldapActive(ctx)
	if cfg == nil {
		return false, errors.New("domain sign-in is disabled")
	}
	err := cfg.VerifyPassword(ctx, u.LDAPDN, password)
	if errors.Is(err, ldapauth.ErrBadCredentials) {
		return false, nil
	}
	return err == nil, err
}

// RunLDAPSync co 5 minut sprawdza konta domenowe w AD: konto usunięte,
// wyłączone albo bez grupy z profilem traci sesje; zmiana grupy zmienia
// profil (działa od razu – uprawnienia liczone przy każdym żądaniu).
func (s *Server) RunLDAPSync(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(ldapSyncEvery):
		}
		if cfg := s.ldapActive(ctx); cfg != nil {
			s.ldapSync(ctx, cfg)
		}
	}
}

func (s *Server) ldapSync(ctx context.Context, cfg *ldapauth.Config) {
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		s.Log.Warn("synchronizacja kont domenowych: lista kont", "err", err)
		return
	}
	for _, u := range users {
		if u.Source != store.SourceLDAP || u.Disabled || u.ExternalID == "" {
			continue
		}
		acct, err := cfg.LookupSID(ctx, u.ExternalID)
		reason := ""
		var m ldapauth.Mapping
		switch {
		case errors.Is(err, ldapauth.ErrNotFound):
			reason = "konto usunięte z AD"
		case err != nil:
			s.Log.Warn("domain account sync: AD unavailable – no changes", "err", err)
			return
		case acct.Disabled:
			reason = "konto wyłączone w AD"
		default:
			var ok bool
			if m, ok = cfg.ProfileFor(acct.GroupSIDs); !ok || !s.profileExists(ctx, m.Profile) {
				reason = "brak grupy przypisanej do profilu"
			}
		}
		s.ldap.mu.Lock()
		if s.ldap.revoked == nil {
			s.ldap.revoked = map[string]bool{}
		}
		already := s.ldap.revoked[u.ExternalID]
		if reason != "" {
			s.ldap.revoked[u.ExternalID] = true
		} else {
			delete(s.ldap.revoked, u.ExternalID)
		}
		s.ldap.mu.Unlock()
		if reason != "" {
			if err := s.Store.DeleteUserSessions(ctx, u.ID, ""); err != nil {
				s.Log.Warn("domain account sync: removing sessions", "user", u.Username, "err", err)
			}
			if !already {
				s.Log.Info("domain account lost access to the panel", "user", u.Username, "reason", reason)
				_ = s.Store.Audit(ctx, store.AuditEntry{Username: "(synchronizacja AD)", Action: "ldap_access_removed",
					Target: u.Username, Details: map[string]any{"reason": reason}})
			}
			continue
		}
		if m.Profile != u.Role {
			role := m.Profile
			if _, err := s.Store.UpdateUser(ctx, u.ID, store.UserPatch{Role: &role}); err != nil {
				s.Log.Warn("synchronizacja kont domenowych: zmiana profilu", "user", u.Username, "err", err)
				continue
			}
			_ = s.Store.Audit(ctx, store.AuditEntry{Username: "(synchronizacja AD)", Action: "ldap_profile_changed",
				Target: u.Username, Details: map[string]any{"from": u.Role, "to": role, "group": m.Name}})
		}
	}
}

// ---- ustawienia (Administracja → Logowanie domenowe) ----

func (s *Server) needLDAP(w http.ResponseWriter) bool {
	if !s.ldapAvailable() {
		writeError(w, http.StatusServiceUnavailable, "ldap_disabled",
			"logowanie domenowe niedostępne – wymaga klucza szyfrującego na serwerze (certs/mfa.key)")
		return false
	}
	return true
}

func (s *Server) getLDAPSettings(w http.ResponseWriter, r *http.Request) {
	if !s.ldapAvailable() {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	cfg, err := s.ldapConfig(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	c := *cfg
	hasPassword := c.BindPassword != ""
	c.BindPassword = ""
	if c.URLs == nil {
		c.URLs = []string{}
	}
	if c.Mappings == nil {
		c.Mappings = []ldapauth.Mapping{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "config": c, "has_password": hasPassword})
}

type ldapDraft struct {
	Config       ldapauth.Config `json:"config"`
	BindPassword string          `json:"bind_password"` // puste – zapisane (tylko przy niezmienionych adresach)
	Login        string          `json:"login"`
	Password     string          `json:"password"` // ponowne podanie hasła (zapis)
}

// draftConfig: ustawienia z formularza. Zapisane hasło konta usługowego
// trafia tylko do tych samych adresów kontrolerów – inaczej administrator
// mógłby je wyprowadzić, kierując test na własny serwer LDAP.
func (s *Server) draftConfig(w http.ResponseWriter, r *http.Request, d *ldapDraft) (*ldapauth.Config, bool) {
	c := d.Config
	c.BindPassword = d.BindPassword
	if c.BindPassword == "" {
		saved, err := s.ldapConfig(r.Context())
		if err != nil {
			s.internalError(w, r, err)
			return nil, false
		}
		if saved != nil && slices.Equal(saved.URLs, c.URLs) && saved.TLSServerName == c.TLSServerName && saved.BindDN == c.BindDN {
			c.BindPassword = saved.BindPassword
		}
	}
	if c.BindPassword == "" {
		writeError(w, http.StatusBadRequest, "bind_password_required",
			"podaj hasło konta usługowego (zapisane trafia tylko do zapisanych adresów kontrolerów)")
		return nil, false
	}
	if err := c.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_config", err)
		return nil, false
	}
	return &c, true
}

func (s *Server) testLDAP(w http.ResponseWriter, r *http.Request) {
	if !s.needLDAP(w) {
		return
	}
	if !s.allow("ldaptest:"+current(r).user.Username, 20, 5) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "zbyt wiele prób – odczekaj chwilę")
		return
	}
	var d ldapDraft
	if !readJSON(w, r, &d) {
		return
	}
	cfg, ok := s.draftConfig(w, r, &d)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := cfg.Test(ctx); err != nil {
		writeJSON(w, http.StatusOK, failed(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "połączenie LDAPS i logowanie kontem usługowym działają"})
}

func (s *Server) ldapGroups(w http.ResponseWriter, r *http.Request) {
	if !s.needLDAP(w) {
		return
	}
	var d ldapDraft
	if !readJSON(w, r, &d) {
		return
	}
	cfg, ok := s.draftConfig(w, r, &d)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	groups, err := cfg.Groups(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ldap_error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

// checkLDAPAccount: podgląd konta (bez hasła) – grupy powiązane z profilami
// i profil, który dostanie przy logowaniu.
func (s *Server) checkLDAPAccount(w http.ResponseWriter, r *http.Request) {
	if !s.needLDAP(w) {
		return
	}
	var d ldapDraft
	if !readJSON(w, r, &d) {
		return
	}
	cfg, ok := s.draftConfig(w, r, &d)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	acct, err := cfg.Lookup(ctx, d.Login)
	if errors.Is(err, ldapauth.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"found": false})
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ldap_error", err)
		return
	}
	has := map[string]bool{}
	for _, g := range acct.GroupSIDs {
		has[g] = true
	}
	matched := []ldapauth.Mapping{}
	for _, m := range cfg.Mappings {
		if has[m.SID] {
			matched = append(matched, m)
		}
	}
	m, ok := cfg.ProfileFor(acct.GroupSIDs)
	out := map[string]any{"found": true, "account": acct, "groups": len(acct.GroupSIDs), "matched": matched}
	if ok && !acct.Disabled {
		out["profile"] = m.Profile
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) saveLDAPSettings(w http.ResponseWriter, r *http.Request) {
	if !s.needLDAP(w) {
		return
	}
	a := current(r)
	var d ldapDraft
	if !readJSON(w, r, &d) {
		return
	}
	c := d.Config
	for i, m := range c.Mappings {
		if m.SID == "" || !s.profileExists(r.Context(), m.Profile) {
			writeError(w, http.StatusBadRequest, "bad_mapping", "powiązanie #"+itoaInt(i+1)+": grupa bez SID albo nieznany profil")
			return
		}
	}
	saved, err := s.ldapConfig(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	// Hasło: nowe z formularza albo zapisane – tylko przy tych samych adresach.
	c.BindPassword = d.BindPassword
	if c.BindPassword == "" && saved != nil && slices.Equal(saved.URLs, c.URLs) && saved.TLSServerName == c.TLSServerName && saved.BindDN == c.BindDN {
		c.BindPassword = saved.BindPassword
	}
	if c.Enabled {
		if err := c.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_config", err)
			return
		}
		if c.BindPassword == "" {
			writeError(w, http.StatusBadRequest, "bind_password_required", "podaj hasło konta usługowego")
			return
		}
	}
	if !s.reauth(w, r, d.Password, "ldap_settings") {
		return
	}
	out := ldapSaved{Config: c}
	out.BindPassword = ""
	if c.BindPassword != "" {
		if out.BindPasswordEnc, err = auth.SealData(s.MFAKey, []byte(c.BindPassword), ldapSecretUsage); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	raw, _ := json.Marshal(out)
	if err := s.MFA.SetSetting(r.Context(), ldapConfigKey, string(raw), a.user.Username, s.now()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.dropLDAPCache()
	groups := make([]string, 0, len(c.Mappings))
	for _, m := range c.Mappings {
		groups = append(groups, m.Name+" → "+m.Profile)
	}
	s.audit(r, &a.user, "ldap_settings_changed", "", map[string]any{"enabled": c.Enabled, "urls": c.URLs, "bind_dn": c.BindDN,
		"base_dn": c.BaseDN, "groups_base_dn": c.GroupsBaseDN, "mappings": groups, "password_changed": d.BindPassword != ""})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func itoaInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
