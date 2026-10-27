// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oidc: logowanie do panelu przez dostawcę tożsamości OpenID Connect
// (wersja 1.6.1, docelowo Microsoft Entra ID). Przepływ authorization code
// z PKCE; token ID sprawdzany tutaj (podpis RS256 kluczem z JWKS dostawcy,
// wystawca, odbiorca, ważność, nonce) – bez zewnętrznych bibliotek.
// Grupy z tokenu (claim „groups” – identyfikatory obiektów grup Entra ID)
// wybierają profil uprawnień panelu, jak grupy AD przy logowaniu domenowym.
package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"siem/internal/lang"
)

// Config to ustawienia logowania (Administracja → Logowanie SSO).
type Config struct {
	Enabled      bool      `json:"enabled"`
	Issuer       string    `json:"issuer"` // np. https://login.microsoftonline.com/<tenant>/v2.0
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"-"`
	RedirectURL  string    `json:"redirect_url"` // https://panel:8444/api/v1/auth/oidc/callback
	ButtonLabel  string    `json:"button_label"` // napis na przycisku logowania
	Mappings     []Mapping `json:"mappings"`     // grupa → profil; pierwsza pasująca wygrywa
}

// Mapping to powiązanie grupy (identyfikator obiektu) z profilem panelu.
type Mapping struct {
	Group   string `json:"group"`
	Name    string `json:"name"` // nazwa do wyświetlenia
	Profile string `json:"profile"`
}

// Validate sprawdza ustawienia przed zapisem albo testem.
func (c *Config) Validate() error {
	u, err := url.Parse(c.Issuer)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "":
		return lang.Errorf("adres wystawcy (issuer) musi być adresem https://", "the issuer must be an https:// URL")
	case strings.TrimSpace(c.ClientID) == "":
		return lang.Errorf("podaj identyfikator aplikacji (client ID)", "enter the application (client) ID")
	case c.ClientSecret == "":
		return lang.Errorf("podaj sekret aplikacji (client secret)", "enter the client secret")
	}
	ru, err := url.Parse(c.RedirectURL)
	if err != nil || ru.Scheme != "https" || ru.Host == "" || !strings.HasSuffix(ru.Path, "/api/v1/auth/oidc/callback") {
		return lang.Errorf("adres powrotu musi być https://…/api/v1/auth/oidc/callback", "the redirect URL must be https://…/api/v1/auth/oidc/callback")
	}
	if len(c.Mappings) == 0 {
		return lang.Errorf("dodaj co najmniej jedno powiązanie grupy z profilem", "add at least one group-to-profile mapping")
	}
	for _, m := range c.Mappings {
		if strings.TrimSpace(m.Group) == "" || m.Profile == "" {
			return lang.Errorf("powiązanie bez grupy albo profilu", "a mapping without a group or profile")
		}
	}
	return nil
}

// ProfileFor: profil z pierwszego powiązania, którego grupę ma konto.
func (c *Config) ProfileFor(groups []string) (Mapping, bool) {
	for _, m := range c.Mappings {
		if slices.ContainsFunc(groups, func(g string) bool { return strings.EqualFold(g, strings.TrimSpace(m.Group)) }) {
			return m, true
		}
	}
	return Mapping{}, false
}

// Claims to dane konta z tokenu ID.
type Claims struct {
	Subject  string   `json:"sub"`
	OID      string   `json:"oid"` // Entra ID: stały identyfikator konta w dzierżawie
	TID      string   `json:"tid"`
	Name     string   `json:"name"`
	Username string   `json:"preferred_username"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	AMR      []string `json:"amr"`
	Nonce    string   `json:"nonce"`
	// Overage: za dużo grup, by zmieściły się w tokenie (Entra ID: > 200).
	Overage bool `json:"-"`
}

// ID: stały identyfikator konta – oid (Entra ID) albo sub.
func (c Claims) ID() string {
	if c.OID != "" {
		return c.OID
	}
	return c.Subject
}

// Login: nazwa konta do wyświetlenia i loginu w panelu.
func (c Claims) Login() string {
	for _, v := range []string{c.Username, c.Email, c.Subject} {
		if v != "" {
			return strings.ToLower(v)
		}
	}
	return ""
}

// MFA: dostawca potwierdził logowanie drugim składnikiem.
func (c Claims) MFA() bool { return slices.Contains(c.AMR, "mfa") }

var (
	ErrToken  = errors.New("oidc: invalid ID token")
	ErrNonce  = errors.New("oidc: nonce mismatch")
	ErrExpiry = errors.New("oidc: ID token expired")
)

type discovery struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
}

// Provider: konfiguracja dostawcy z discovery i klucze (z pamięcią podręczną).
type Provider struct {
	HTTP *http.Client
	Now  func() time.Time

	mu      sync.Mutex
	issuer  string
	disc    *discovery
	discAt  time.Time
	keys    map[string]*rsa.PublicKey
	keysAt  time.Time
	keysTry time.Time
}

func (p *Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Provider) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (p *Provider) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// Discover pobiera (albo zwraca zapamiętaną na godzinę) konfigurację dostawcy.
func (p *Provider) Discover(ctx context.Context, issuer string) (*discovery, error) {
	p.mu.Lock()
	if p.disc != nil && p.issuer == issuer && p.now().Sub(p.discAt) < time.Hour {
		d := p.disc
		p.mu.Unlock()
		return d, nil
	}
	p.mu.Unlock()
	var d discovery
	if err := p.getJSON(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &d); err != nil {
		return nil, lang.Errorf("pobranie konfiguracji dostawcy nieudane: %w", "fetching the provider configuration failed: %w", err)
	}
	for _, u := range []string{d.AuthURL, d.TokenURL, d.JWKSURL} {
		if pu, err := url.Parse(u); err != nil || pu.Scheme != "https" {
			return nil, lang.Errorf("konfiguracja dostawcy: adres bez https", "provider configuration: a non-https endpoint")
		}
	}
	if d.Issuer != issuer {
		return nil, lang.Errorf("wystawca z konfiguracji dostawcy (%s) różni się od ustawionego", "the issuer in the provider configuration (%s) differs from the configured one", d.Issuer)
	}
	p.mu.Lock()
	if p.issuer != issuer {
		p.keys = nil
	}
	p.issuer, p.disc, p.discAt = issuer, &d, p.now()
	p.mu.Unlock()
	return &d, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// key zwraca klucz o danym kid; nieznany kid – ponowne pobranie JWKS (rotacja
// kluczy), najwyżej raz na minutę.
func (p *Provider) key(ctx context.Context, d *discovery, kid string) (*rsa.PublicKey, error) {
	p.mu.Lock()
	k := p.keys[kid]
	fresh := p.keys != nil && p.now().Sub(p.keysAt) < 24*time.Hour
	recent := p.now().Sub(p.keysTry) < time.Minute
	p.mu.Unlock()
	if k != nil && fresh {
		return k, nil
	}
	if recent && k == nil && p.keys != nil {
		return nil, ErrToken
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	p.mu.Lock()
	p.keysTry = p.now()
	p.mu.Unlock()
	if err := p.getJSON(ctx, d.JWKSURL, &set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || (j.Use != "" && j.Use != "sig") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(j.N)
		e, err2 := base64.RawURLEncoding.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		keys[j.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	p.mu.Lock()
	p.keys, p.keysAt = keys, p.now()
	p.mu.Unlock()
	if k := keys[kid]; k != nil {
		return k, nil
	}
	return nil, ErrToken
}

// Challenge: PKCE – weryfikator i jego skrót S256.
func Challenge() (verifier, challenge string) {
	verifier = RandomString(32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// RandomString: losowy tekst (base64url) z n bajtów.
func RandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthURL: adres logowania u dostawcy. reauth – ponowne uwierzytelnienie
// (prompt=login, max_age=0), loginHint – podpowiedź konta.
func (p *Provider) AuthURL(ctx context.Context, c *Config, state, nonce, challenge string, reauth bool, loginHint string) (string, error) {
	d, err := p.Discover(ctx, c.Issuer)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_id": {c.ClientID}, "response_type": {"code"}, "redirect_uri": {c.RedirectURL},
		"scope": {"openid profile email"}, "state": {state}, "nonce": {nonce}, "response_mode": {"query"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	if reauth {
		q.Set("prompt", "login")
		q.Set("max_age", "0")
	}
	if loginHint != "" {
		q.Set("login_hint", loginHint)
	}
	sep := "?"
	if strings.Contains(d.AuthURL, "?") {
		sep = "&"
	}
	return d.AuthURL + sep + q.Encode(), nil
}

// Exchange wymienia kod na tokeny i zwraca sprawdzone dane z tokenu ID.
func (p *Provider) Exchange(ctx context.Context, c *Config, code, verifier, nonce string) (Claims, error) {
	d, err := p.Discover(ctx, c.Issuer)
	if err != nil {
		return Claims{}, err
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {c.RedirectURL},
		"client_id": {c.ClientID}, "client_secret": {c.ClientSecret}, "code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Claims{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client().Do(req)
	if err != nil {
		return Claims{}, err
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return Claims{}, fmt.Errorf("token endpoint: HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || tok.IDToken == "" {
		// Opis błędu dostawcy (np. AADSTS7000215 – zły sekret) bez treści tokenów.
		desc := tok.Desc
		if i := strings.IndexAny(desc, "\r\n"); i >= 0 {
			desc = desc[:i]
		}
		return Claims{}, fmt.Errorf("token endpoint: HTTP %d %s %s", resp.StatusCode, tok.Error, desc)
	}
	return p.Verify(ctx, c, tok.IDToken, nonce)
}

// Verify sprawdza token ID: RS256, klucz dostawcy, wystawca, odbiorca,
// ważność (z 2 min tolerancji zegara) i nonce.
func (p *Provider) Verify(ctx context.Context, c *Config, raw, nonce string) (Claims, error) {
	d, err := p.Discover(ctx, c.Issuer)
	if err != nil {
		return Claims{}, err
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, ErrToken
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodePart(parts[0], &hdr); err != nil || hdr.Alg != "RS256" {
		return Claims{}, ErrToken
	}
	key, err := p.key(ctx, d, hdr.Kid)
	if err != nil {
		return Claims{}, ErrToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrToken
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) != nil {
		return Claims{}, ErrToken
	}
	var std struct {
		Iss        string          `json:"iss"`
		Aud        json.RawMessage `json:"aud"`
		Exp        float64         `json:"exp"`
		Nbf        float64         `json:"nbf"`
		ClaimNames map[string]any  `json:"_claim_names"`
	}
	var cl Claims
	if decodePart(parts[1], &std) != nil || decodePart(parts[1], &cl) != nil {
		return Claims{}, ErrToken
	}
	if std.Iss != d.Issuer || !audience(std.Aud, c.ClientID) {
		return Claims{}, ErrToken
	}
	now := p.now()
	skew := 2 * time.Minute
	if std.Exp == 0 || now.After(time.Unix(int64(std.Exp), 0).Add(skew)) {
		return Claims{}, ErrExpiry
	}
	if std.Nbf != 0 && now.Add(skew).Before(time.Unix(int64(std.Nbf), 0)) {
		return Claims{}, ErrToken
	}
	if nonce == "" || cl.Nonce != nonce {
		return Claims{}, ErrNonce
	}
	if cl.ID() == "" {
		return Claims{}, ErrToken
	}
	_, cl.Overage = std.ClaimNames["groups"]
	return cl, nil
}

func audience(raw json.RawMessage, clientID string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == clientID
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && slices.Contains(many, clientID)
}

func decodePart(s string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
