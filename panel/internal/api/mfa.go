// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
)

// MFAStore to drugi składnik logowania (TOTP) i ustawienia panelu
// (implementuje store.PG). Opcjonalne: bez niego (i bez klucza MFAKey)
// panel loguje samym hasłem.
type MFAStore interface {
	MFAState(ctx context.Context, userID int64) (store.MFA, error)
	MFAEnabledUsers(ctx context.Context) (map[int64]time.Time, error)
	EnableMFA(ctx context.Context, userID int64, secretEnc []byte, step int64, codeHashes []string, now time.Time) error
	ReplaceRecoveryCodes(ctx context.Context, userID int64, codeHashes []string) error
	DisableMFA(ctx context.Context, userID int64) error
	AdvanceMFAStep(ctx context.Context, userID, step int64) (bool, error)
	UseRecoveryCode(ctx context.Context, userID int64, codeHash string, now time.Time) (bool, int, error)
	MarkSessionMFA(ctx context.Context, id string) error
	Setting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value, by string, now time.Time) error
}

// Polityka MFA (ustawienie panelu): kogo obowiązuje drugi składnik.
const (
	mfaAll    = "all"    // wszystkie konta (domyślnie)
	mfaAdmins = "admins" // administratorzy
	mfaNone   = "none"   // nikt (dobrowolnie)

	mfaPolicyKey   = "mfa_policy"
	mfaIssuer      = "Vardr"
	mfaChallengeTL = 5 * time.Minute
	mfaSetupTL     = 10 * time.Minute
	mfaMaxAttempts = 5
)

// mfaState: oczekujące logowania (hasło sprawdzone, czeka na kod) i
// konfiguracje TOTP (wylosowany sekret do potwierdzenia kodem) – w pamięci,
// krótko; restart siem-api je unieważnia. Polityka – z pamięci podręcznej.
type mfaState struct {
	mu        sync.Mutex
	pending   map[string]*mfaChallenge
	policy    string
	policyAt  time.Time
	policyErr error
}

type mfaChallenge struct {
	userID   int64
	expires  time.Time
	attempts int
	enroll   bool   // konto bez drugiego składnika, a polityka go wymaga
	secret   []byte // konfiguracja: sekret do potwierdzenia
}

func (s *Server) mfaEnabled() bool { return s.MFA != nil && len(s.MFAKey) == 32 }

// mfaPolicy: obowiązująca polityka (pamięć podręczna 15 s; błąd bazy –
// ostatnia znana albo „wszyscy”: przy awarii nie luzujemy wymagań).
func (s *Server) mfaPolicy(ctx context.Context) string {
	if !s.mfaEnabled() {
		return mfaNone
	}
	st := &s.mfa
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.policy != "" && s.now().Sub(st.policyAt) < 15*time.Second {
		return st.policy
	}
	v, err := s.MFA.Setting(ctx, mfaPolicyKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
		v = mfaAll
	case err != nil:
		s.Log.Warn("reading the MFA policy failed", "err", err)
		if st.policy != "" {
			return st.policy
		}
		return mfaAll
	}
	st.policy, st.policyAt = v, s.now()
	return v
}

// mfaRequired: polityka wymaga drugiego składnika od tego konta.
func (s *Server) mfaRequired(ctx context.Context, u store.User) bool {
	switch s.mfaPolicy(ctx) {
	case mfaAll:
		return true
	case mfaAdmins:
		return s.permsOf(ctx, u.Role).Admin()
	}
	return false
}

func (s *Server) newChallenge(key string, c *mfaChallenge) {
	st := &s.mfa
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pending == nil {
		st.pending = map[string]*mfaChallenge{}
	}
	now := s.now()
	if len(st.pending) > 10000 {
		for k, v := range st.pending {
			if now.After(v.expires) {
				delete(st.pending, k)
			}
		}
	}
	st.pending[key] = c
}

// challenge zwraca oczekujące logowanie albo konfigurację (nil – brak/wygasło).
func (s *Server) challenge(key string) *mfaChallenge {
	st := &s.mfa
	st.mu.Lock()
	defer st.mu.Unlock()
	c := st.pending[key]
	if c != nil && s.now().After(c.expires) {
		delete(st.pending, key)
		return nil
	}
	return c
}

func (s *Server) dropChallenge(key string) {
	s.mfa.mu.Lock()
	delete(s.mfa.pending, key)
	s.mfa.mu.Unlock()
}

// failChallenge liczy nieudaną próbę; po mfaMaxAttempts logowanie trzeba zacząć od nowa.
func (s *Server) failChallenge(key string) {
	s.mfa.mu.Lock()
	defer s.mfa.mu.Unlock()
	if c := s.mfa.pending[key]; c != nil {
		if c.attempts++; c.attempts >= mfaMaxAttempts {
			delete(s.mfa.pending, key)
		}
	}
}

// checkCode sprawdza kod TOTP albo kod zapasowy konta. method: totp | recovery.
func (s *Server) checkCode(ctx context.Context, userID int64, code string) (ok bool, method string, left int, err error) {
	st, err := s.MFA.MFAState(ctx, userID)
	if err != nil {
		return false, "", 0, err
	}
	if auth.LooksLikeRecovery(code) {
		ok, left, err := s.MFA.UseRecoveryCode(ctx, userID, auth.RecoveryHash(code), s.now())
		return ok, "recovery", left, err
	}
	secret, err := auth.OpenSecret(s.MFAKey, st.SecretEnc, userID)
	if err != nil {
		return false, "", 0, err
	}
	step, ok := auth.VerifyTOTP(secret, code, s.now(), st.LastStep)
	if !ok {
		return false, "totp", st.RecoveryLeft, nil
	}
	ok, err = s.MFA.AdvanceMFAStep(ctx, userID, step)
	return ok, "totp", st.RecoveryLeft, err
}

// mfaSetup: nowy sekret z kodem QR do aplikacji uwierzytelniającej.
func mfaSetup(username string, secret []byte) (map[string]any, error) {
	uri := auth.OTPAuthURI(mfaIssuer, username, secret)
	qr, err := auth.QRDataURL(uri)
	if err != nil {
		return nil, err
	}
	return map[string]any{"secret": auth.SecretText(secret), "uri": uri, "qr": qr, "issuer": mfaIssuer, "account": username}, nil
}

// enableMFA zapisuje sekret po potwierdzeniu kodem; zwraca kody zapasowe.
func (s *Server) enableMFA(ctx context.Context, userID int64, secret []byte, code string) ([]string, bool, error) {
	step, ok := auth.VerifyTOTP(secret, code, s.now(), 0)
	if !ok {
		return nil, false, nil
	}
	sealed, err := auth.SealSecret(s.MFAKey, secret, userID)
	if err != nil {
		return nil, false, err
	}
	codes := auth.NewRecoveryCodes()
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = auth.RecoveryHash(c)
	}
	return codes, true, s.MFA.EnableMFA(ctx, userID, sealed, step, hashes, s.now())
}

type mfaLoginRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

// loginChallenge: wspólny początek kroków logowania z drugim składnikiem.
func (s *Server) loginChallenge(w http.ResponseWriter, r *http.Request, req *mfaLoginRequest) (string, *mfaChallenge, store.User, bool) {
	if !s.mfaEnabled() {
		writeError(w, http.StatusNotFound, "mfa_disabled", "drugi składnik logowania nie jest skonfigurowany")
		return "", nil, store.User{}, false
	}
	if !s.allow("login:"+clientIP(r), 10, 10) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "zbyt wiele prób logowania – odczekaj minutę")
		return "", nil, store.User{}, false
	}
	if !readJSON(w, r, req) {
		return "", nil, store.User{}, false
	}
	key := "login:" + auth.TokenID(req.Challenge)
	c := s.challenge(key)
	if req.Challenge == "" || c == nil {
		writeError(w, http.StatusUnauthorized, "mfa_expired", "logowanie wygasło – podaj login i hasło jeszcze raz")
		return "", nil, store.User{}, false
	}
	user, err := s.Store.UserByID(r.Context(), c.userID)
	if err != nil || user.Disabled || (user.LockedUntil != nil && user.LockedUntil.After(s.now())) {
		s.dropChallenge(key)
		writeError(w, http.StatusUnauthorized, "bad_credentials", badLogin)
		return "", nil, store.User{}, false
	}
	return key, c, user, true
}

// badMFA: nieudany kod przy logowaniu – liczy się do blokady konta.
func (s *Server) badMFA(w http.ResponseWriter, r *http.Request, key string, user store.User, reason string) {
	s.failChallenge(key)
	if until, err := s.Store.RecordLoginFailure(r.Context(), user.ID, s.LockAfter, s.LockFor); err == nil && until != nil && until.After(s.now()) {
		reason += "_locked"
		s.dropChallenge(key)
	}
	s.audit(r, &user, "login_failed", user.Username, map[string]any{"reason": reason})
	writeError(w, http.StatusUnauthorized, "bad_mfa", "nieprawidłowy kod")
}

// loginMFA: drugi krok logowania – kod z aplikacji albo kod zapasowy.
func (s *Server) loginMFA(w http.ResponseWriter, r *http.Request) {
	var req mfaLoginRequest
	key, c, user, ok := s.loginChallenge(w, r, &req)
	if !ok {
		return
	}
	if c.enroll {
		writeError(w, http.StatusBadRequest, "enroll_required", "najpierw skonfiguruj aplikację uwierzytelniającą")
		return
	}
	valid, method, left, err := s.checkCode(r.Context(), user.ID, req.Code)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !valid {
		s.badMFA(w, r, key, user, "bad_mfa")
		return
	}
	s.dropChallenge(key)
	extra := map[string]any{"mfa_method": method}
	if method == "recovery" {
		s.audit(r, &user, "mfa_recovery_used", user.Username, map[string]any{"left": left})
		extra["recovery_left"] = left
	}
	s.finishLogin(w, r, user, true, extra)
}

// loginEnroll: konfiguracja TOTP przy logowaniu (polityka wymaga, konto nie ma).
func (s *Server) loginEnroll(w http.ResponseWriter, r *http.Request) {
	var req mfaLoginRequest
	_, c, user, ok := s.loginChallenge(w, r, &req)
	if !ok {
		return
	}
	if !c.enroll {
		writeError(w, http.StatusBadRequest, "already_enrolled", "konto ma już drugi składnik")
		return
	}
	s.mfa.mu.Lock()
	if c.secret == nil {
		c.secret = auth.NewTOTPSecret()
	}
	secret := c.secret
	s.mfa.mu.Unlock()
	out, err := mfaSetup(user.Username, secret)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// loginEnrollConfirm: potwierdzenie konfiguracji kodem – zapis i zalogowanie.
func (s *Server) loginEnrollConfirm(w http.ResponseWriter, r *http.Request) {
	var req mfaLoginRequest
	key, c, user, ok := s.loginChallenge(w, r, &req)
	if !ok {
		return
	}
	if !c.enroll || c.secret == nil {
		writeError(w, http.StatusBadRequest, "no_setup", "najpierw wyświetl kod QR")
		return
	}
	codes, valid, err := s.enableMFA(r.Context(), user.ID, c.secret, req.Code)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !valid {
		s.badMFA(w, r, key, user, "bad_mfa_setup")
		return
	}
	s.dropChallenge(key)
	s.audit(r, &user, "mfa_enabled", user.Username, map[string]any{"during_login": true})
	s.finishLogin(w, r, user, true, map[string]any{"mfa_method": "totp", "recovery_codes": codes})
}

// ---- moje konto ----

func (s *Server) accountMFA(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	out := map[string]any{"available": s.mfaEnabled(), "enabled": false, "policy": s.mfaPolicy(r.Context()),
		"required": s.mfaRequired(r.Context(), a.user), "session_mfa": a.session.MFA, "sso": a.user.Source == store.SourceOIDC}
	if s.mfaEnabled() {
		st, err := s.MFA.MFAState(r.Context(), a.user.ID)
		switch {
		case err == nil:
			out["enabled"], out["enabled_at"], out["recovery_left"] = true, st.EnabledAt, st.RecoveryLeft
		case !errors.Is(err, store.ErrNotFound):
			s.internalError(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) needMFA(w http.ResponseWriter) bool {
	if !s.mfaEnabled() {
		writeError(w, http.StatusServiceUnavailable, "mfa_disabled",
			"drugi składnik niedostępny – brak klucza MFA na serwerze (SIEM_MFA_KEY_FILE)")
		return false
	}
	return true
}

// accountMFASetup: nowy sekret (po haśle) – potwierdzenie kodem w accountMFAConfirm.
func (s *Server) accountMFASetup(w http.ResponseWriter, r *http.Request) {
	if !s.needMFA(w) {
		return
	}
	a := current(r)
	var req struct {
		Password string `json:"password"`
	}
	if a.user.Source == store.SourceOIDC {
		// Konto SSO potwierdza drugi składnik u dostawcy – kod panelu nie
		// byłby sprawdzany przy logowaniu.
		writeError(w, http.StatusConflict, "sso_account", "konto SSO – drugi składnik zapewnia dostawca tożsamości (Entra ID)")
		return
	}
	if !readJSON(w, r, &req) || !s.reauth(w, r, req.Password, "mfa_setup") {
		return
	}
	secret := auth.NewTOTPSecret()
	s.newChallenge("setup:"+a.session.ID, &mfaChallenge{userID: a.user.ID, expires: s.now().Add(mfaSetupTL), secret: secret})
	out, err := mfaSetup(a.user.Username, secret)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) accountMFAConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.needMFA(w) {
		return
	}
	a := current(r)
	var req struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	key := "setup:" + a.session.ID
	c := s.challenge(key)
	if c == nil || c.userID != a.user.ID {
		writeError(w, http.StatusBadRequest, "no_setup", "konfiguracja wygasła – zacznij od nowa")
		return
	}
	codes, valid, err := s.enableMFA(r.Context(), a.user.ID, c.secret, req.Code)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !valid {
		s.failChallenge(key)
		writeError(w, http.StatusBadRequest, "bad_mfa", "nieprawidłowy kod – sprawdź czas w telefonie i spróbuj ponownie")
		return
	}
	s.dropChallenge(key)
	if err := s.MFA.MarkSessionMFA(r.Context(), a.session.ID); err != nil {
		s.Log.Warn("marking the MFA session failed", "err", err)
	}
	// Inne sesje konta powstały bez drugiego składnika – koniec z nimi.
	if err := s.Store.DeleteUserSessions(r.Context(), a.user.ID, a.session.ID); err != nil {
		s.Log.Error("removing other sessions failed", "err", err)
	}
	s.audit(r, &a.user, "mfa_enabled", a.user.Username, nil)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// accountMFACode: hasło i kod (TOTP albo zapasowy) – wyłączenie i nowe kody zapasowe.
func (s *Server) accountMFACode(w http.ResponseWriter, r *http.Request, op string) (store.User, bool) {
	a := current(r)
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &req) || !s.reauth(w, r, req.Password, op) {
		return a.user, false
	}
	valid, _, _, err := s.checkCode(r.Context(), a.user.ID, req.Code)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "mfa_not_enabled", "konto nie ma drugiego składnika")
		return a.user, false
	}
	if err != nil {
		s.internalError(w, r, err)
		return a.user, false
	}
	if !valid {
		s.audit(r, &a.user, "reauth_failed", a.user.Username, map[string]any{"operation": op, "reason": "bad_mfa"})
		writeError(w, http.StatusBadRequest, "bad_mfa", "nieprawidłowy kod")
		return a.user, false
	}
	return a.user, true
}

func (s *Server) accountMFADisable(w http.ResponseWriter, r *http.Request) {
	if !s.needMFA(w) {
		return
	}
	a := current(r)
	if s.mfaRequired(r.Context(), a.user) {
		writeError(w, http.StatusBadRequest, "mfa_required_by_policy", "polityka panelu wymaga drugiego składnika od tego konta")
		return
	}
	u, ok := s.accountMFACode(w, r, "mfa_disable")
	if !ok {
		return
	}
	if err := s.MFA.DisableMFA(r.Context(), u.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &u, "mfa_disabled", u.Username, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) accountMFARecovery(w http.ResponseWriter, r *http.Request) {
	if !s.needMFA(w) {
		return
	}
	u, ok := s.accountMFACode(w, r, "mfa_recovery_codes")
	if !ok {
		return
	}
	codes := auth.NewRecoveryCodes()
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = auth.RecoveryHash(c)
	}
	if err := s.MFA.ReplaceRecoveryCodes(r.Context(), u.ID, hashes); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &u, "mfa_recovery_regenerated", u.Username, nil)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// ---- administracja ----

// resetUserMFA usuwa drugi składnik konta (zgubiony telefon) i jego sesje –
// przy następnym logowaniu użytkownik skonfiguruje aplikację od nowa.
func (s *Server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	if !s.needMFA(w) {
		return
	}
	a := current(r)
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator konta")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) || !s.reauth(w, r, req.Password, "mfa_reset") {
		return
	}
	target, err := s.Store.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego konta")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.MFA.DisableMFA(r.Context(), id); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.Store.DeleteUserSessions(r.Context(), id, ""); err != nil {
		s.Log.Error("removing the account sessions failed", "user_id", id, "err", err)
	}
	s.audit(r, &a.user, "mfa_reset", target.Username, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) securitySettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"mfa_available": s.mfaEnabled(), "mfa_policy": s.mfaPolicy(r.Context())})
}

// setSecuritySettings: polityka MFA. Zawsze z hasłem (ustawienie
// bezpieczeństwa); administrator, którego nowa polityka obejmie, musi
// najpierw sam mieć drugi składnik w tej sesji – inaczej odciąłby sam siebie.
func (s *Server) setSecuritySettings(w http.ResponseWriter, r *http.Request) {
	if !s.needMFA(w) {
		return
	}
	a := current(r)
	var req struct {
		MFAPolicy string `json:"mfa_policy"`
		Password  string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.MFAPolicy != mfaAll && req.MFAPolicy != mfaAdmins && req.MFAPolicy != mfaNone {
		writeError(w, http.StatusBadRequest, "bad_policy", "mfa_policy: all, admins albo none")
		return
	}
	if !s.reauth(w, r, req.Password, "mfa_policy") {
		return
	}
	if req.MFAPolicy != mfaNone && !a.session.MFA {
		writeError(w, http.StatusBadRequest, "enroll_first",
			"najpierw włącz drugi składnik na swoim koncie (Moje konto → Bezpieczeństwo) – inaczej panel wylogowałby także Ciebie")
		return
	}
	prev := s.mfaPolicy(r.Context())
	if err := s.MFA.SetSetting(r.Context(), mfaPolicyKey, req.MFAPolicy, a.user.Username, s.now()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.mfa.mu.Lock()
	s.mfa.policy = ""
	s.mfa.mu.Unlock()
	s.audit(r, &a.user, "mfa_policy_changed", req.MFAPolicy, map[string]any{"from": prev, "to": req.MFAPolicy})
	writeJSON(w, http.StatusOK, map[string]any{"mfa_policy": req.MFAPolicy})
}
