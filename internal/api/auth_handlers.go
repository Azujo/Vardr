package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"siem/internal/api/auth"
	"siem/internal/api/store"
)

// Poziomy ról (wyższa obejmuje niższe).
type roleLevel int

const (
	roleViewer roleLevel = iota + 1
	roleAnalyst
	roleAdmin
)

func levelOf(role string) roleLevel {
	switch role {
	case store.RoleAdmin:
		return roleAdmin
	case store.RoleAnalyst:
		return roleAnalyst
	case store.RoleViewer:
		return roleViewer
	}
	return 0
}

// Flagi dla authed.
const allowPasswordChange = 1 // dostępne także przed wymaganą zmianą hasła

type ctxKey struct{}

type authCtx struct {
	session store.Session
	user    store.User
}

func current(r *http.Request) authCtx {
	a, _ := r.Context().Value(ctxKey{}).(authCtx)
	return a
}

// authed wymaga ważnej sesji, odpowiedniej roli i – dla zmian – tokenu CSRF.
func (s *Server) authed(need roleLevel, flags int, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if levelOf(user.Role) < need {
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
				s.Log.Warn("przedłużenie sesji nieudane", "err", err)
			}
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, authCtx{session: sess, user: user})
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
}

const badLogin = "nieprawidłowy login lub hasło albo konto tymczasowo zablokowane"

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.allowLogin(ip) {
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
			s.Log.Warn("konto zablokowane po nieudanych logowaniach", "username", user.Username, "ip", ip, "until", until)
		}
		s.audit(r, &user, "login_failed", user.Username, map[string]any{"reason": reason})
		writeError(w, http.StatusUnauthorized, "bad_credentials", badLogin)
		return
	}

	if err := s.Store.RecordLoginSuccess(r.Context(), user.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	if rehash { // parametry hasha podniesione od czasu ustawienia hasła
		if h, err := auth.HashPassword(req.Password); err == nil {
			_ = s.Store.SetPassword(r.Context(), user.ID, h, user.MustChangePassword)
		}
	}
	token := auth.NewToken()
	sess := store.Session{
		ID: auth.TokenID(token), UserID: user.ID, CSRF: auth.NewToken(),
		CreatedAt: now, ExpiresAt: now.Add(s.IdleTimeout), IP: ip, UserAgent: truncate(r.UserAgent(), 256),
	}
	if err := s.Store.CreateSession(r.Context(), sess); err != nil {
		s.internalError(w, r, err)
		return
	}
	setCookie(w, token, s.MaxAge)
	s.audit(r, &user, "login", user.Username, nil)
	writeJSON(w, http.StatusOK, sessionResponse{User: user, CSRFToken: sess.CSRF})
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	writeJSON(w, http.StatusOK, sessionResponse{User: a.user, CSRFToken: a.session.CSRF})
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
		writeError(w, http.StatusBadRequest, "weak_password", err.Error())
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
		s.Log.Error("usunięcie innych sesji nieudane", "err", err)
	}
	s.audit(r, &a.user, "password_changed", a.user.Username, nil)
	a.user.MustChangePassword = false
	writeJSON(w, http.StatusOK, sessionResponse{User: a.user, CSRFToken: a.session.CSRF})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
