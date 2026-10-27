// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
	"siem/panel/internal/oidc"
)

// memOIDC: konta SSO w memStore.
type memOIDC struct {
	st  *memStore
	ext map[string]int64
}

func (m *memOIDC) UpsertOIDCUser(ctx context.Context, u store.User) (store.User, error) {
	if id, ok := m.ext[u.ExternalID]; ok {
		m.st.mu.Lock()
		x := m.st.users[id]
		x.Username, x.DisplayName, x.Role = u.Username, u.DisplayName, u.Role
		m.st.users[id] = x
		m.st.mu.Unlock()
		return x, nil
	}
	if _, err := m.st.UserByUsername(ctx, u.Username); err == nil {
		return store.User{}, store.ErrConflict
	}
	u.Source, u.PasswordHash = store.SourceOIDC, "!oidc"
	c, err := m.st.CreateUser(ctx, u)
	if err == nil {
		m.ext[u.ExternalID] = c.ID
	}
	return c, err
}

func (m *memOIDC) UserByExternalID(_ context.Context, id string) (store.User, error) {
	uid, ok := m.ext[id]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	return m.st.users[uid], nil
}

func (m *memOIDC) SetSessionReauth(_ context.Context, id string, at time.Time) error {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	s := m.st.sessions[id]
	s.ReauthAt = &at
	m.st.sessions[id] = s
	return nil
}

// testIdP: dostawca OIDC – discovery, klucze i token z ostatnio ustawionymi danymi konta.
type testIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any // bez nonce – dopisywany z adresu logowania
	nonce  string
}

func newTestIdP(t *testing.T) *testIdP {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &testIdP{key: k}
	mux := http.NewServeMux()
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	mux.HandleFunc("/tenant/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": p.srv.URL + "/tenant/v2.0", "authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k", "n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.PostForm.Get("code") != "dobry-kod" || r.PostForm.Get("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		c := map[string]any{"iss": p.srv.URL + "/tenant/v2.0", "aud": "vardr-app", "nonce": p.nonce,
			"exp": time.Date(2026, 10, 20, 11, 0, 0, 0, time.UTC).Unix()}
		for k, v := range p.claims {
			c[k] = v
		}
		enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
		h, b := enc(map[string]string{"alg": "RS256", "kid": "k"}), enc(c)
		sum := sha256.Sum256([]byte(h + "." + b))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		json.NewEncoder(w).Encode(map[string]string{"id_token": h + "." + b + "." + base64.RawURLEncoding.EncodeToString(sig)})
	})
	return p
}

// ssoEnv: panel z włączonym logowaniem SSO (grupa „g-analityk” → analityk).
func ssoEnv(t *testing.T, policy string) (*env, *testIdP, *Server) {
	e := &env{t: t, clock: time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)}
	e.st = newMemStore(func() time.Time { return e.clock })
	m := newMemMFA(e.st)
	m.settings[mfaPolicyKey] = policy
	idp := newTestIdP(t)
	key := []byte(strings.Repeat("k", 32))
	sec, _ := auth.SealData(key, []byte("sekret"), oidcSecretUsage)
	raw, _ := json.Marshal(oidcSaved{Config: oidc.Config{Enabled: true, Issuer: idp.srv.URL + "/tenant/v2.0", ClientID: "vardr-app",
		RedirectURL: "https://panel/api/v1/auth/oidc/callback", Mappings: []oidc.Mapping{{Group: "g-analityk", Profile: store.RoleAnalyst}}},
		ClientSecretEnc: sec})
	m.settings[oidcConfigKey] = string(raw)
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), UI: fstest.MapFS{"index.html": {Data: []byte("x")}},
		MFA: m, MFAKey: key, OIDC: &memOIDC{st: e.st, ext: map[string]int64{}}}
	srv.now = func() time.Time { return e.clock }
	srv.sso.provider = oidc.Provider{HTTP: idp.srv.Client(), Now: srv.now}
	e.h = srv.Handler()
	return e, idp, srv
}

// ssoLogin: przycisk → dostawca → powrót z kodem; zwraca odpowiedź powrotu.
func ssoLogin(t *testing.T, e *env, idp *testIdP, c *client, start, code string) *http.Response {
	t.Helper()
	_, _, res := c.do("GET", start, nil)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("start: %d", res.StatusCode)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	idp.nonce = loc.Query().Get("nonce")
	var state *http.Cookie
	for _, ck := range res.Cookies() {
		if ck.Name == oidcStateCookie {
			state = ck
		}
	}
	if state == nil || state.SameSite != http.SameSiteLaxMode || loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("start: ciasteczko %v, adres %s", state, loc)
	}
	r := httptest.NewRequest("GET", "https://panel/api/v1/auth/oidc/callback?code="+code+"&state="+url.QueryEscape(loc.Query().Get("state")), nil)
	r.RemoteAddr = c.ip + ":5000"
	r.AddCookie(state)
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	out := w.Result()
	for _, ck := range out.Cookies() {
		if ck.Name == cookieName && ck.MaxAge > 0 {
			c.cookie = ck
		}
	}
	return out
}

func refreshTarget(t *testing.T, res *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(res.Body)
	i := strings.Index(string(b), "url=")
	if i < 0 {
		t.Fatalf("brak przekierowania: %d %s", res.StatusCode, b)
	}
	rest := string(b)[i+4:]
	return html.UnescapeString(rest[:strings.Index(rest, `"`)])
}

// Logowanie SSO: konto zakładane z profilem z grupy, sesja; bez grupy,
// bez MFA przy polityce, ze złym stanem albo kodem – odmowa; ponowne
// uwierzytelnienie zastępuje hasło przez 5 minut.
func TestOIDCLogin(t *testing.T) {
	e, idp, srv := ssoEnv(t, mfaAll)
	if code, out, _ := e.client("10.0.0.1").do("GET", "/api/v1/auth/oidc", nil); code != 200 || out["enabled"] != true {
		t.Fatalf("informacja: %d %v", code, out)
	}

	// Bez MFA u dostawcy przy polityce „wszyscy” – odmowa.
	idp.claims = map[string]any{"oid": "o-1", "preferred_username": "Jan@Firma.pl", "name": "Jan K", "groups": []string{"G-ANALITYK"}, "amr": []string{"pwd"}}
	c := e.client("10.0.0.1")
	if got := refreshTarget(t, ssoLogin(t, e, idp, c, "/api/v1/auth/oidc/start", "dobry-kod")); got != "/login?sso_error=no_mfa" || c.cookie != nil {
		t.Fatalf("bez MFA: %s", got)
	}
	// Z MFA – sesja, konto z profilem z grupy.
	idp.claims["amr"] = []string{"pwd", "mfa"}
	if got := refreshTarget(t, ssoLogin(t, e, idp, c, "/api/v1/auth/oidc/start", "dobry-kod")); got != "/" || c.cookie == nil {
		t.Fatalf("logowanie: %s", got)
	}
	code, out, _ := c.do("GET", "/api/v1/auth/session", nil)
	user, _ := out["user"].(map[string]any)
	if code != 200 || user["username"] != "jan@firma.pl" || user["role"] != store.RoleAnalyst || user["source"] != "oidc" || out["mfa"] != true {
		t.Fatalf("sesja: %d %v", code, out)
	}
	c.csrf = out["csrf_token"].(string)
	// Aplikacji TOTP panelu konto SSO nie włącza – drugi składnik u dostawcy.
	if code, out, _ := c.do("GET", "/api/v1/account/mfa", nil); code != 200 || out["sso"] != true {
		t.Fatalf("stan MFA: %d %v", code, out)
	}
	if code, out, _ := c.do("POST", "/api/v1/account/mfa/setup", map[string]any{"password": "x"}); code != 409 || out["error"] != "sso_account" {
		t.Fatalf("TOTP dla konta SSO: %d %v", code, out)
	}

	// Hasło konta SSO nie działa w zwykłym logowaniu.
	if code, _ := e.client("10.0.0.2").login("jan@firma.pl", "!oidc"); code != 401 {
		t.Fatalf("hasło konta SSO: %d", code)
	}
	// Operacja chroniona: bez potwierdzenia u dostawcy – reauth_sso;
	// po potwierdzeniu (to samo konto) – dozwolona przez 5 minut.
	a := authCtx{user: srv.mustUser(t, e, "jan@firma.pl")}
	if srv.ssoReauthOK(a) {
		t.Fatal("potwierdzenie bez logowania u dostawcy")
	}
	if got := refreshTarget(t, ssoLogin(t, e, idp, c, "/api/v1/auth/oidc/start?reauth=1", "dobry-kod")); got != "/sso/done?result=ok" {
		t.Fatalf("potwierdzenie: %s", got)
	}
	sess, _, _ := e.st.SessionWithUser(context.Background(), auth.TokenID(c.cookie.Value), e.clock)
	a.session = sess
	if !srv.ssoReauthOK(a) {
		t.Fatal("potwierdzenie nie zapisane w sesji")
	}
	e.clock = e.clock.Add(6 * time.Minute)
	if srv.ssoReauthOK(a) {
		t.Fatal("potwierdzenie ważne po 6 minutach")
	}
	// Potwierdzenie innym kontem – odmowa.
	idp.claims["oid"] = "o-2"
	if got := refreshTarget(t, ssoLogin(t, e, idp, c, "/api/v1/auth/oidc/start?reauth=1", "dobry-kod")); got != "/sso/done?result=error&code=other_account" {
		t.Fatalf("inne konto: %s", got)
	}

	// Konto bez grupy z profilem, zły kod, zły stan.
	idp.claims = map[string]any{"oid": "o-3", "preferred_username": "obcy@firma.pl", "groups": []string{"inna"}, "amr": []string{"mfa"}}
	d := e.client("10.0.0.3")
	if got := refreshTarget(t, ssoLogin(t, e, idp, d, "/api/v1/auth/oidc/start", "dobry-kod")); got != "/login?sso_error=no_access" || d.cookie != nil {
		t.Fatalf("bez grupy: %s", got)
	}
	if got := refreshTarget(t, ssoLogin(t, e, idp, d, "/api/v1/auth/oidc/start", "zly-kod")); got != "/login?sso_error=token" {
		t.Fatalf("zły kod: %s", got)
	}
	r := httptest.NewRequest("GET", "https://panel/api/v1/auth/oidc/callback?code=dobry-kod&state=podrobiony", nil)
	r.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: "inny"})
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if got := refreshTarget(t, w.Result()); got != "/login?sso_error=state" {
		t.Fatalf("zły stan: %s", got)
	}
}

func (s *Server) mustUser(t *testing.T, e *env, name string) store.User {
	t.Helper()
	u, err := e.st.UserByUsername(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
