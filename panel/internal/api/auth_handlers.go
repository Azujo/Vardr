// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"siem/internal/svc"
	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
	"siem/panel/internal/perm"
)

// Flagi dla authed.
const (
	allowPasswordChange = 1 << iota // dostępne także przed wymaganą zmianą hasła
	// allowToken: trasa „tylko zalogowanie” (loggedIn) dostępna też dla
	// tokenu API. Trasy z uprawnieniem modułu są dla tokenów zawsze.
	allowToken
)

type ctxKey struct{}

type authCtx struct {
	session store.Session
	user    store.User
	perms   perm.Set // uprawnienia profilu konta
	// token: żądanie z tokenem API (wtedy bez sesji; user – aktor api:<nazwa>).
	token *store.APIToken
}

func current(r *http.Request) authCtx {
	a, _ := r.Context().Value(ctxKey{}).(authCtx)
	return a
}

// authed wymaga ważnej sesji, uprawnienia profilu konta (moduł, poziom;
// loggedIn – samo zalogowanie) i – dla zmian – tokenu CSRF. Żądanie
// z nagłówkiem Authorization to program z tokenem API (tokenAuthed).
func (s *Server) authed(req need, flags int, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hdr := r.Header.Get("Authorization"); hdr != "" {
			s.tokenAuthed(w, r, req, flags, hdr, h)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "zaloguj się")
			return
		}
		now := s.now()
		sess, user, err := s.Store.SessionWithUser(r.Context(), auth.TokenID(c.Value), now)
		switch {
		case errors.Is(err, store.ErrNotFound):
			clearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "sesja wygasła – zaloguj się ponownie")
			return
		case err != nil:
			s.internalError(w, r, err)
			return
		case user.Disabled:
			_ = s.Store.DeleteSession(r.Context(), sess.ID)
			clearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "konto jest wyłączone")
			return
		case !sess.MFA && s.mfaEnabled() && s.mfaRequired(r.Context(), user):
			// Polityka wymaga drugiego składnika, a sesja powstała bez niego
			// (np. sprzed włączenia wymogu) – logowanie od nowa, z kodem.
			_ = s.Store.DeleteSession(r.Context(), sess.ID)
			clearCookie(w)
			writeError(w, http.StatusUnauthorized, "mfa_required", "panel wymaga drugiego składnika logowania – zaloguj się ponownie")
			return
		}

		// Żądania zmieniające stan muszą nieść token CSRF z sesji (obok
		// SameSite=Strict – dwie niezależne bariery).
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			got := r.Header.Get(csrfHeader)
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRF)) != 1 {
				writeError(w, http.StatusForbidden, "csrf", "brak lub niepoprawny token CSRF – odśwież stronę")
				return
			}
		}
		if user.MustChangePassword && flags&allowPasswordChange == 0 {
			writeError(w, http.StatusForbidden, "password_change_required", "najpierw zmień hasło startowe")
			return
		}
		perms := s.permsOf(r.Context(), user.Role)
		if req != loggedIn && !perms.Has(req.mod, req.level) {
			writeError(w, http.StatusForbidden, "forbidden", "brak uprawnień do tej operacji")
			return
		}

		// Przesunięcie limitu bezczynności (nie częściej niż co minutę).
		if now.Sub(sess.LastSeenAt) > time.Minute {
			expires := now.Add(s.IdleTimeout)
			if hard := sess.CreatedAt.Add(s.MaxAge); hard.Before(expires) {
				expires = hard
			}
			if err := s.Store.TouchSession(r.Context(), sess.ID, now, expires); err != nil {
				s.Log.Warn("extending the session failed", "err", err)
			}
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, authCtx{session: sess, user: user, perms: perms})
		h(w, r.WithContext(ctx))
	})
}

func setCookie(w http.ResponseWriter, token string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", MaxAge: int(maxAge.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

type sessionResponse struct {
	User      store.User `json:"user"`
	CSRFToken string     `json:"csrf_token"`
	// ServerVersion: wersja siem-api (ustawiana przy budowaniu, deploy.sh).
	ServerVersion string `json:"server_version"`
	// MFA: sesja potwierdzona drugim składnikiem.
	MFA bool `json:"mfa"`
	// Profil konta i jego uprawnienia (panel ukrywa niedostępne moduły).
	Profile     profileRef `json:"profile"`
	Permissions perm.Set   `json:"permissions"`
}

type profileRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// sessionInfo: odpowiedź z kontem, profilem i uprawnieniami.
func (s *Server) sessionInfo(ctx context.Context, u store.User, csrf string, mfa bool) sessionResponse {
	p := s.profiles(ctx)[u.Role]
	name := p.Name
	if name == "" {
		name = u.Role
	}
	return sessionResponse{User: u, CSRFToken: csrf, ServerVersion: svc.Version, MFA: mfa,
		Profile: profileRef{ID: u.Role, Name: name}, Permissions: s.permsOf(ctx, u.Role)}
}

const badLogin = "nieprawidłowy login lub hasło albo konto tymczasowo zablokowane"

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.allow("login:"+ip, 10, 10) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "zbyt wiele prób logowania – odczekaj minutę")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	now := s.now()

	user, err := s.Store.UserByUsername(r.Context(), req.Username)
	// Konto domenowe (albo nieznane lokalnie przy włączonym logowaniu
	// domenowym, także FIRMA\jan i jan@firma.pl) – sprawdza AD.
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.Source == store.SourceLDAP) {
		if cfg := s.ldapActive(r.Context()); cfg != nil {
			s.ldapLogin(w, r, cfg, req.Username, req.Password)
			return
		}
	}
	if err == nil && user.Source == store.SourceLDAP {
		auth.DummyVerify(req.Password)
		s.audit(r, &user, "login_failed", user.Username, map[string]any{"reason": "ldap_disabled"})
		writeError(w, http.StatusUnauthorized, "bad_credentials", badLogin)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		auth.DummyVerify(req.Password) // ten sam czas odpowiedzi co dla istniejącego konta
		s.audit(r, nil, "login_failed", req.Username, map[string]any{"reason": "unknown_user"})
		writeError(w, http.StatusUnauthorized, "bad_credentials", badLogin)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		auth.DummyVerify(req.Password)
		s.audit(r, &user, "login_failed", user.Username, map[string]any{"reason": "locked"})
		writeError(w, http.StatusUnauthorized, "bad_credentials", badLogin)
		return
	}
	ok, rehash, err := auth.VerifyPassword(user.PasswordHash, req.Password)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !ok || user.Disabled {
		reason := "bad_password"
		if ok {
			reason = "disabled"
		} else if until, err := s.Store.RecordLoginFailure(r.Context(), user.ID, s.LockAfter, s.LockFor); err == nil && until != nil && until.After(now) {
			reason = "bad_password_locked"
			s.Log.Warn("account locked after failed sign-ins", "username", user.Username, "ip", ip, "until", until)
		}
		s.audit(r, &user, "login_failed", user.Username, map[string]any{"reason": reason})
		writeError(w, http.StatusUnauthorized, "bad_credentials", badLogin)
		return
	}

	if rehash { // parametry hasha podniesione od czasu ustawienia hasła
		if h, err := auth.HashPassword(req.Password); err == nil {
			_ = s.Store.SetPassword(r.Context(), user.ID, h, user.MustChangePassword)
		}
	}
	s.afterPassword(w, r, user)
}

// afterPassword: hasło (lokalne albo domenowe) sprawdzone. Drugi składnik:
// konto go ma albo polityka wymaga – sesja dopiero po kodzie (albo po
// konfiguracji aplikacji); inaczej sesja od razu.
func (s *Server) afterPassword(w http.ResponseWriter, r *http.Request, user store.User) {
	now := s.now()
	if s.mfaEnabled() {
		_, err := s.MFA.MFAState(r.Context(), user.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, r, err)
			return
		}
		enrolled := err == nil
		if enrolled || s.mfaRequired(r.Context(), user) {
			token := auth.NewToken()
			s.newChallenge("login:"+auth.TokenID(token), &mfaChallenge{userID: user.ID, expires: now.Add(mfaChallengeTL), enroll: !enrolled})
			step := "code"
			if !enrolled {
				step = "enroll"
			}
			writeJSON(w, http.StatusOK, map[string]any{"mfa": step, "challenge": token, "username": user.Username})
			return
		}
	}
	s.finishLogin(w, r, user, false, nil)
}

// finishLogin zakłada sesję po udanym logowaniu (hasło, a gdy trzeba – kod).
// extra: dodatkowe pola odpowiedzi i wpisu audytu (np. kody zapasowe – tylko
// w odpowiedzi).
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, user store.User, mfa bool, extra map[string]any) {
	now := s.now()
	if err := s.Store.RecordLoginSuccess(r.Context(), user.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	token := auth.NewToken()
	sess := store.Session{
		ID: auth.TokenID(token), UserID: user.ID, CSRF: auth.NewToken(),
		CreatedAt: now, ExpiresAt: now.Add(s.IdleTimeout), IP: clientIP(r), UserAgent: truncate(r.UserAgent(), 256), MFA: mfa,
	}
	if err := s.Store.CreateSession(r.Context(), sess); err != nil {
		s.internalError(w, r, err)
		return
	}
	setCookie(w, token, s.MaxAge)
	details := map[string]any{}
	if m, ok := extra["mfa_method"]; ok {
		details["mfa"] = m
	}
	s.audit(r, &user, "login", user.Username, details)
	si := s.sessionInfo(r.Context(), user, sess.CSRF, mfa)
	out := map[string]any{"user": user, "csrf_token": sess.CSRF, "server_version": svc.Version, "mfa": mfa,
		"profile": si.Profile, "permissions": si.Permissions}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	writeJSON(w, http.StatusOK, s.sessionInfo(r.Context(), a.user, a.session.CSRF, a.session.MFA))
}

// panelLanguages: języki, w których panel ma tłumaczenia ("" – z przeglądarki).
var panelLanguages = []string{"", "pl", "en"}

// accountLanguage zapisuje język panelu wybrany przez użytkownika. To
// ustawienie tylko jego konta – nie zmienia języka powiadomień ani zgłoszeń.
func (s *Server) accountLanguage(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	var req struct {
		Language string `json:"language"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !slices.Contains(panelLanguages, req.Language) {
		writeError(w, http.StatusBadRequest, "bad_language", "nieobsługiwany język")
		return
	}
	u, err := s.Store.UpdateUser(r.Context(), a.user.ID, store.UserPatch{Language: &req.Language})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"language": u.Language})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	if err := s.Store.DeleteSession(r.Context(), a.session.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	clearCookie(w)
	s.audit(r, &a.user, "logout", a.user.Username, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	if a.user.Source == store.SourceLDAP {
		writeError(w, http.StatusBadRequest, "ldap_account", "hasło konta domenowego zmienia się w Active Directory")
		return
	}
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ok, _, err := auth.VerifyPassword(a.user.PasswordHash, req.Current)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !ok {
		s.audit(r, &a.user, "password_change_failed", a.user.Username, map[string]any{"reason": "bad_current"})
		writeError(w, http.StatusBadRequest, "bad_current_password", "obecne hasło jest nieprawidłowe")
		return
	}
	if req.New == req.Current {
		writeError(w, http.StatusBadRequest, "weak_password", "nowe hasło musi różnić się od obecnego")
		return
	}
	if err := auth.CheckPasswordPolicy(a.user.Username, req.New); err != nil {
		writeErr(w, http.StatusBadRequest, "weak_password", err)
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.Store.SetPassword(r.Context(), a.user.ID, hash, false); err != nil {
		s.internalError(w, r, err)
		return
	}
	// Inne sesje tego konta (np. na skradzionym laptopie) przestają działać.
	if err := s.Store.DeleteUserSessions(r.Context(), a.user.ID, a.session.ID); err != nil {
		s.Log.Error("removing other sessions failed", "err", err)
	}
	s.audit(r, &a.user, "password_changed", a.user.Username, nil)
	a.user.MustChangePassword = false
	writeJSON(w, http.StatusOK, s.sessionInfo(r.Context(), a.user, a.session.CSRF, a.session.MFA))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
