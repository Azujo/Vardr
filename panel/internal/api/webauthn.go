// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"siem/panel/internal/api/store"
	"siem/panel/internal/webauthn"
)

// Klucze bezpieczeństwa i passkeys (WebAuthn) – drugi składnik obok
// aplikacji TOTP: konto musi najpierw mieć TOTP (kody zapasowe i aplikacja
// zostają drogą awaryjną, reset MFA usuwa też klucze). Przy logowaniu
// użytkownik wybiera klucz albo kod. Wymaga otwierania panelu po nazwie
// (WebAuthn nie działa na adresie IP) i HTTPS.

const (
	webauthnTimeoutMS = 120000
	webauthnNameMax   = 64
)

// webauthnRP: identyfikator strony z adresu, pod którym otwarto panel.
func webauthnRP(r *http.Request) (string, error) { return webauthn.RPID(r.Host) }

// webauthnUserHandle: stały, nieujawniający identyfikator konta dla klucza.
func webauthnUserHandle(userID int64) []byte {
	h := sha256.Sum256([]byte("vardr-user:" + strconv.FormatInt(userID, 10)))
	return h[:16]
}

func credDescriptors(keys []store.WebAuthnKey, rpID string) []map[string]any {
	out := []map[string]any{}
	for _, k := range keys {
		if k.RPID == rpID {
			out = append(out, map[string]any{"type": "public-key", "id": webauthn.B64(k.CredentialID)})
		}
	}
	return out
}

// ---- logowanie ----

// loginWebAuthnBegin: wyzwanie dla klucza (po haśle, zamiast kodu).
func (s *Server) loginWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	var req mfaLoginRequest
	_, c, user, ok := s.loginChallenge(w, r, &req)
	if !ok {
		return
	}
	if c.enroll {
		writeError(w, http.StatusBadRequest, "enroll_required", "najpierw skonfiguruj aplikację uwierzytelniającą")
		return
	}
	rpID, err := webauthnRP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "webauthn_needs_name", err.Error())
		return
	}
	keys, err := s.MFA.WebAuthnKeys(r.Context(), user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	allow := credDescriptors(keys, rpID)
	if len(allow) == 0 {
		writeError(w, http.StatusBadRequest, "webauthn_no_keys", "konto nie ma klucza bezpieczeństwa dla tego adresu panelu – użyj kodu")
		return
	}
	ch := webauthn.NewChallenge()
	s.mfa.mu.Lock()
	c.waChallenge, c.waRP = ch, rpID
	s.mfa.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": map[string]any{
		"challenge": webauthn.B64(ch), "rpId": rpID, "allowCredentials": allow,
		"timeout": webauthnTimeoutMS, "userVerification": "preferred"}})
}

type webauthnAssertion struct {
	Challenge         string `json:"challenge"`
	ID                string `json:"id"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

// loginWebAuthn: podpis klucza – sprawdzenie i zalogowanie.
func (s *Server) loginWebAuthn(w http.ResponseWriter, r *http.Request) {
	var req webauthnAssertion
	if !s.loginAllowed(w, r) || !readJSON(w, r, &req) {
		return
	}
	key, c, user, ok := s.pendingLogin(w, r, req.Challenge)
	if !ok {
		return
	}
	s.mfa.mu.Lock()
	ch, rpID := c.waChallenge, c.waRP
	c.waChallenge = nil // wyzwanie jednorazowe
	s.mfa.mu.Unlock()
	if ch == nil {
		writeError(w, http.StatusBadRequest, "webauthn_no_challenge", "najpierw rozpocznij logowanie kluczem")
		return
	}
	k, err := s.verifyAssertion(r, user.ID, rpID, ch, req)
	if errors.Is(err, errNoSuchKey) || errors.Is(err, errKeyReplayed) || isWebAuthnErr(err) {
		s.Log.Warn("security key sign-in rejected", "username", user.Username, "err", err)
		s.badMFA(w, r, key, user, "bad_webauthn")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.dropChallenge(key)
	s.finishLogin(w, r, user, true, map[string]any{"mfa_method": "webauthn", "key": k.Name})
}

var (
	errNoSuchKey   = errors.New("webauthn: unknown key")
	errKeyReplayed = errors.New("webauthn: signature counter already used")
)

func isWebAuthnErr(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "webauthn:")
}

// verifyAssertion sprawdza podpis kluczem konta i zapisuje licznik.
func (s *Server) verifyAssertion(r *http.Request, userID int64, rpID string, ch []byte, req webauthnAssertion) (store.WebAuthnKey, error) {
	id, err1 := webauthn.FromB64(req.ID)
	cd, err2 := webauthn.FromB64(req.ClientDataJSON)
	ad, err3 := webauthn.FromB64(req.AuthenticatorData)
	sig, err4 := webauthn.FromB64(req.Signature)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return store.WebAuthnKey{}, webauthn.ErrBadClientData
	}
	keys, err := s.MFA.WebAuthnKeys(r.Context(), userID)
	if err != nil {
		return store.WebAuthnKey{}, err
	}
	for _, k := range keys {
		if !bytes.Equal(k.CredentialID, id) || k.RPID != rpID {
			continue
		}
		cred := webauthn.Credential{ID: k.CredentialID, PublicKey: k.PublicKey, Alg: k.Alg, SignCount: k.SignCount, RPID: k.RPID}
		n, uv, err := webauthn.Verify(cred, ch, webauthn.Assertion{ClientDataJSON: cd, AuthenticatorData: ad, Signature: sig})
		if err != nil {
			return k, err
		}
		used, err := s.MFA.UseWebAuthnKey(r.Context(), k.ID, n, uv, s.now())
		if err != nil {
			return k, err
		}
		if !used {
			return k, errKeyReplayed
		}
		return k, nil
	}
	return store.WebAuthnKey{}, errNoSuchKey
}

// ---- moje konto ----

// accountWebAuthn: klucze konta i czy można je tu dodać.
func (s *Server) accountWebAuthn(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	out := map[string]any{"available": s.mfaEnabled() && a.user.Source != store.SourceOIDC, "keys": []store.WebAuthnKey{}}
	rpID, err := webauthnRP(r)
	if err != nil {
		out["rp_error"] = "webauthn_needs_name"
	} else {
		out["rp_id"] = rpID
	}
	if s.mfaEnabled() {
		keys, err := s.MFA.WebAuthnKeys(r.Context(), a.user.ID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		out["keys"] = keys
	}
	writeJSON(w, http.StatusOK, out)
}

// accountWebAuthnBegin: hasło – opcje rejestracji nowego klucza.
func (s *Server) accountWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	if !s.needMFA(w) {
		return
	}
	a := current(r)
	if a.user.Source == store.SourceOIDC {
		writeError(w, http.StatusConflict, "sso_account", "konto SSO – drugi składnik zapewnia dostawca tożsamości (Entra ID)")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	rpID, err := webauthnRP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "webauthn_needs_name", err.Error())
		return
	}
	if _, err := s.MFA.MFAState(r.Context(), a.user.ID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "totp_first", "najpierw włącz aplikację uwierzytelniającą (TOTP) – zostaje drogą awaryjną")
		return
	} else if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !s.reauth(w, r, req.Password, "webauthn_add") {
		return
	}
	keys, err := s.MFA.WebAuthnKeys(r.Context(), a.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(keys) >= store.MaxWebAuthnKeys {
		writeError(w, http.StatusConflict, "webauthn_limit", "osiągnięto limit kluczy konta – usuń nieużywany")
		return
	}
	ch := webauthn.NewChallenge()
	s.newChallenge("webauthn:"+a.session.ID, &mfaChallenge{userID: a.user.ID, expires: s.now().Add(mfaSetupTL), waChallenge: ch, waRP: rpID})
	params := make([]map[string]any, 0, len(webauthn.Algorithms))
	for _, alg := range webauthn.Algorithms {
		params = append(params, map[string]any{"type": "public-key", "alg": alg})
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": map[string]any{
		"rp":        map[string]any{"id": rpID, "name": mfaIssuer},
		"user":      map[string]any{"id": webauthn.B64(webauthnUserHandle(a.user.ID)), "name": a.user.Username, "displayName": a.user.Username},
		"challenge": webauthn.B64(ch), "pubKeyCredParams": params, "timeout": webauthnTimeoutMS,
		"attestation": "none", "excludeCredentials": credDescriptors(keys, rpID),
		"authenticatorSelection": map[string]any{"residentKey": "discouraged", "userVerification": "preferred"}}})
}

// accountWebAuthnFinish: odpowiedź klucza – zapis.
func (s *Server) accountWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	if !s.needMFA(w) {
		return
	}
	a := current(r)
	var req struct {
		Name              string `json:"name"`
		ClientDataJSON    string `json:"client_data_json"`
		AttestationObject string `json:"attestation_object"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || utf8.RuneCountInString(req.Name) > webauthnNameMax {
		writeError(w, http.StatusBadRequest, "bad_name", "nazwa klucza: 1–64 znaki")
		return
	}
	key := "webauthn:" + a.session.ID
	c := s.challenge(key)
	if c == nil || c.userID != a.user.ID || c.waChallenge == nil {
		writeError(w, http.StatusBadRequest, "no_setup", "rejestracja wygasła – zacznij od nowa")
		return
	}
	s.dropChallenge(key)
	cd, err1 := webauthn.FromB64(req.ClientDataJSON)
	att, err2 := webauthn.FromB64(req.AttestationObject)
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusBadRequest, "webauthn_invalid", "niepoprawna odpowiedź klucza")
		return
	}
	cred, err := webauthn.Register(c.waRP, c.waChallenge, cd, att)
	if err != nil {
		s.Log.Warn("security key registration rejected", "username", a.user.Username, "err", err)
		writeError(w, http.StatusBadRequest, "webauthn_invalid", "niepoprawna odpowiedź klucza: "+err.Error())
		return
	}
	k := store.WebAuthnKey{UserID: a.user.ID, CredentialID: cred.ID, PublicKey: cred.PublicKey, Alg: cred.Alg, RPID: cred.RPID,
		Name: req.Name, AAGUID: cred.AAGUID, SignCount: cred.SignCount, UV: cred.UV, CreatedAt: s.now()}
	id, err := s.MFA.AddWebAuthnKey(r.Context(), k)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "webauthn_exists", "ten klucz jest już zarejestrowany albo osiągnięto limit kluczy")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	k.ID = id
	s.audit(r, &a.user, "webauthn_added", a.user.Username, map[string]any{"key": k.Name, "rp_id": k.RPID, "uv": k.UV})
	writeJSON(w, http.StatusOK, map[string]any{"key": k})
}

// accountWebAuthnDelete: hasło – usunięcie klucza (TOTP zostaje).
func (s *Server) accountWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	if !s.needMFA(w) {
		return
	}
	a := current(r)
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator klucza")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) || !s.reauth(w, r, req.Password, "webauthn_remove") {
		return
	}
	k, err := s.MFA.DeleteWebAuthnKey(r.Context(), a.user.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego klucza")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "webauthn_removed", a.user.Username, map[string]any{"key": k.Name})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
