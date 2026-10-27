// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeIdP: dostawca OIDC na httptest (discovery, JWKS, token).
type fakeIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	idToken  string
	gotForm  url.Values
	tokenErr bool
}

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: k}
	mux := http.NewServeMux()
	f.srv = httptest.NewTLSServer(mux)
	mux.HandleFunc("/t/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": f.issuer(), "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.gotForm = r.PostForm
		if f.tokenErr {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": "AADSTS7000215: bad secret\r\nTrace"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.idToken, "access_token": "x"})
	})
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) issuer() string { return f.srv.URL + "/t/v2.0" }

func (f *fakeIdP) sign(t *testing.T, claims map[string]any, kid string) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	head := enc(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	body := enc(claims)
	sum := sha256.Sum256([]byte(head + "." + body))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyAndExchange(t *testing.T) {
	f := newIdP(t)
	now := time.Now()
	p := &Provider{HTTP: f.srv.Client(), Now: func() time.Time { return now }}
	c := &Config{Issuer: f.issuer(), ClientID: "app", ClientSecret: "s", RedirectURL: "https://panel/api/v1/auth/oidc/callback"}
	good := func() map[string]any {
		return map[string]any{"iss": f.issuer(), "aud": "app", "exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-time.Minute).Unix(),
			"nonce": "n1", "oid": "o-1", "sub": "s-1", "preferred_username": "Jan@Firma.PL", "name": "Jan",
			"groups": []string{"G-A", "g-b"}, "amr": []string{"pwd", "mfa"}}
	}
	ctx := context.Background()
	cl, err := p.Verify(ctx, c, f.sign(t, good(), "k1"), "n1")
	if err != nil || cl.ID() != "o-1" || cl.Login() != "jan@firma.pl" || !cl.MFA() || cl.Overage {
		t.Fatalf("poprawny token: %+v %v", cl, err)
	}

	bad := map[string]func(m map[string]any){
		"aud":    func(m map[string]any) { m["aud"] = "inna" },
		"iss":    func(m map[string]any) { m["iss"] = "https://evil/v2.0" },
		"exp":    func(m map[string]any) { m["exp"] = now.Add(-time.Hour).Unix() },
		"nbf":    func(m map[string]any) { m["nbf"] = now.Add(time.Hour).Unix() },
		"nonce":  func(m map[string]any) { m["nonce"] = "inny" },
		"no id":  func(m map[string]any) { delete(m, "oid"); delete(m, "sub") },
		"aud []": func(m map[string]any) { m["aud"] = []string{"x", "y"} },
	}
	for name, mod := range bad {
		m := good()
		mod(m)
		if _, err := p.Verify(ctx, c, f.sign(t, m, "k1"), "n1"); err == nil {
			t.Errorf("%s: przyjęty", name)
		}
	}
	m := good()
	m["aud"] = []string{"x", "app"}
	if _, err := p.Verify(ctx, c, f.sign(t, m, "k1"), "n1"); err != nil {
		t.Errorf("aud jako lista: %v", err)
	}
	// Podpis innym kluczem, zmieniona treść, alg none.
	tok := f.sign(t, good(), "k1")
	parts := strings.Split(tok, ".")
	other := good()
	other["oid"] = "admin"
	b, _ := json.Marshal(other)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(b) + "." + parts[2]
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`)) + "." + parts[1] + "."
	for name, raw := range map[string]string{"zmieniona treść": forged, "alg none": none, "nieznany kid": f.sign(t, good(), "k2")} {
		if _, err := p.Verify(ctx, c, raw, "n1"); err == nil {
			t.Errorf("%s: przyjęty", name)
		}
	}
	// Za dużo grup (Entra ID: _claim_names).
	m = good()
	delete(m, "groups")
	m["_claim_names"] = map[string]string{"groups": "src1"}
	if cl, err := p.Verify(ctx, c, f.sign(t, m, "k1"), "n1"); err != nil || !cl.Overage {
		t.Fatalf("overage: %+v %v", cl, err)
	}

	// Wymiana kodu: PKCE i sekret w formularzu.
	f.idToken = f.sign(t, good(), "k1")
	cl, err = p.Exchange(ctx, c, "code1", "ver1", "n1")
	if err != nil || cl.ID() != "o-1" {
		t.Fatalf("exchange: %+v %v", cl, err)
	}
	if f.gotForm.Get("code_verifier") != "ver1" || f.gotForm.Get("client_secret") != "s" || f.gotForm.Get("code") != "code1" {
		t.Fatalf("formularz: %v", f.gotForm)
	}
	f.tokenErr = true
	if _, err := p.Exchange(ctx, c, "code1", "ver1", "n1"); err == nil || strings.Contains(err.Error(), "Trace") {
		t.Fatalf("błąd dostawcy: %v", err)
	}

	u, err := p.AuthURL(ctx, c, "st", "n1", "ch", true, "jan@firma.pl")
	if err != nil || !strings.Contains(u, "prompt=login") || !strings.Contains(u, "code_challenge=ch") || !strings.HasPrefix(u, f.srv.URL+"/authorize?") {
		t.Fatalf("auth url: %s %v", u, err)
	}
}

func TestProfileForAndValidate(t *testing.T) {
	c := Config{Issuer: "https://login.microsoftonline.com/t/v2.0", ClientID: "a", ClientSecret: "s",
		RedirectURL: "https://siem:8444/api/v1/auth/oidc/callback",
		Mappings:    []Mapping{{Group: "AAA", Profile: "admin"}, {Group: "bbb", Profile: "analyst"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if m, ok := c.ProfileFor([]string{"BBB", "aaa"}); !ok || m.Profile != "admin" {
		t.Fatalf("kolejność: %+v", m)
	}
	if _, ok := c.ProfileFor([]string{"ccc"}); ok {
		t.Fatal("brak grupy – profil")
	}
	c.RedirectURL = "https://evil/callback"
	if c.Validate() == nil {
		t.Fatal("zły adres powrotu przyjęty")
	}
}
