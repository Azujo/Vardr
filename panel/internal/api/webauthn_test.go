// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"strings"
	"testing"
	"time"

	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
	"siem/panel/internal/webauthn"
	"siem/panel/internal/webauthn/webauthntest"
)

// Klucz bezpieczeństwa: dodanie (po TOTP, z hasłem), logowanie kluczem
// zamiast kodu, odrzucenie powtórzonego podpisu i obcego klucza, usunięcie.
func TestWebAuthnFlow(t *testing.T) {
	e, _ := newMFAEnv(t, mfaNone)
	e.addUser("adam", store.RoleAnalyst, "bardzo-tajne-haslo-1", false)
	a := e.client("10.0.0.1")
	if code, _ := a.login("adam", "bardzo-tajne-haslo-1"); code != 200 {
		t.Fatal("logowanie")
	}
	key := webauthntest.New("panel", "https://panel")

	// Bez TOTP – najpierw aplikacja.
	if code, out, _ := a.do("POST", "/api/v1/account/webauthn", map[string]string{"password": "bardzo-tajne-haslo-1"}); code != 400 || out["error"] != "totp_first" {
		t.Fatalf("bez TOTP: %d %v", code, out)
	}
	_, setup, _ := a.do("POST", "/api/v1/account/mfa/setup", map[string]string{"password": "bardzo-tajne-haslo-1"})
	secret, _ := b32.DecodeString(strings.ReplaceAll(setup["secret"].(string), " ", ""))
	a.do("POST", "/api/v1/account/mfa/confirm", map[string]string{"code": auth.TOTPCode(secret, e.clock)})

	if code, _, _ := a.do("POST", "/api/v1/account/webauthn", map[string]string{"password": "złe"}); code == 200 {
		t.Fatal("rejestracja bez hasła")
	}
	code, opts, _ := a.do("POST", "/api/v1/account/webauthn", map[string]string{"password": "bardzo-tajne-haslo-1"})
	pk, _ := opts["publicKey"].(map[string]any)
	if code != 200 || pk["rp"].(map[string]any)["id"] != "panel" || pk["attestation"] != "none" {
		t.Fatalf("opcje rejestracji: %d %v", code, opts)
	}
	ch, _ := webauthn.FromB64(pk["challenge"].(string))
	cd, att := key.Create(ch)
	code, out, _ := a.do("POST", "/api/v1/account/webauthn/confirm", map[string]string{"name": "YubiKey 5", "client_data_json": cd, "attestation_object": att})
	if code != 200 {
		t.Fatalf("rejestracja: %d %v", code, out)
	}
	// Wyzwanie jednorazowe.
	if code, _, _ := a.do("POST", "/api/v1/account/webauthn/confirm", map[string]string{"name": "x", "client_data_json": cd, "attestation_object": att}); code != 400 {
		t.Fatalf("powtórna rejestracja tym samym wyzwaniem: %d", code)
	}
	_, list, _ := a.do("GET", "/api/v1/account/webauthn", nil)
	keys := list["keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["name"] != "YubiKey 5" || list["rp_id"] != "panel" {
		t.Fatalf("lista: %v", list)
	}

	// Logowanie kluczem; replay – podpis z wcześniejszego logowania.
	login := func(c *client, k *webauthntest.Authenticator, replay []string) (int, map[string]any, []string) {
		_, out, _ := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "adam", "password": "bardzo-tajne-haslo-1"})
		if out["mfa"] != "code" || out["webauthn"] != true {
			t.Fatalf("krok po haśle: %v", out)
		}
		challenge := out["challenge"].(string)
		code, opts, _ := c.do("POST", "/api/v1/auth/webauthn/begin", map[string]string{"challenge": challenge})
		if code != 200 {
			t.Fatalf("begin: %d %v", code, opts)
		}
		pk := opts["publicKey"].(map[string]any)
		ch, _ := webauthn.FromB64(pk["challenge"].(string))
		id, cd, ad, sig := k.Get(ch)
		if replay != nil {
			id, cd, ad, sig = replay[0], replay[1], replay[2], replay[3]
		}
		code, out, _ = c.do("POST", "/api/v1/auth/webauthn", map[string]string{"challenge": challenge, "id": id,
			"client_data_json": cd, "authenticator_data": ad, "signature": sig})
		return code, out, []string{id, cd, ad, sig}
	}
	b := e.client("10.0.0.2")
	code, out, used := login(b, key, nil)
	if code != 200 || b.cookie == nil || out["mfa"] != true {
		t.Fatalf("logowanie kluczem: %d %v", code, out)
	}
	if code, _, _ := login(e.client("10.0.0.3"), key, used); code != 401 {
		t.Fatalf("powtórzony podpis: %d", code)
	}
	if code, _, _ := login(e.client("10.0.0.4"), webauthntest.New("panel", "https://panel"), nil); code != 401 {
		t.Fatalf("obcy klucz: %d", code)
	}
	e.clock = e.clock.Add(time.Minute)
	if code, _, _ := login(e.client("10.0.0.5"), key, nil); code != 200 {
		t.Fatalf("drugie logowanie kluczem: %d", code)
	}

	// Usunięcie z hasłem; potem logowanie tylko kodem.
	id := itoa(int64(keys[0].(map[string]any)["id"].(float64)))
	if code, _, _ := a.do("POST", "/api/v1/account/webauthn/"+id+"/delete", map[string]string{"password": "złe"}); code == 200 {
		t.Fatal("usunięcie bez hasła")
	}
	if code, _, _ := a.do("POST", "/api/v1/account/webauthn/"+id+"/delete", map[string]string{"password": "bardzo-tajne-haslo-1"}); code != 200 {
		t.Fatalf("usunięcie: %d", code)
	}
	_, out, _ = e.client("10.0.0.6").do("POST", "/api/v1/auth/login", map[string]string{"username": "adam", "password": "bardzo-tajne-haslo-1"})
	if out["mfa"] != "code" || out["webauthn"] != nil {
		t.Fatalf("po usunięciu klucza: %v", out)
	}
	for _, want := range []string{"webauthn_added", "webauthn_removed"} {
		found := false
		for _, x := range e.st.actions() {
			found = found || x == want
		}
		if !found {
			t.Errorf("brak wpisu audytu %s: %v", want, e.st.actions())
		}
	}
}
