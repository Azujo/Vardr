// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
	"siem/internal/msipatch"
	"siem/panel/internal/api/store"
	"siem/panel/internal/enroll"
)

// ---- atrapa bazy: tokeny i certyfikaty ----

func (m *memStore) CreateEnrollToken(_ context.Context, t store.EnrollToken) (store.EnrollToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	t.ID, t.CreatedAt = m.nextID, m.now()
	m.tokens = append(m.tokens, t)
	return t, nil
}
func (m *memStore) ListEnrollTokens(context.Context) ([]store.EnrollToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.EnrollToken(nil), m.tokens...), nil
}
func (m *memStore) RevokeEnrollToken(_ context.Context, id int64) (store.EnrollToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.tokens {
		if t.ID == id {
			now := m.now()
			m.tokens[i].RevokedAt = &now
			return m.tokens[i], nil
		}
	}
	return store.EnrollToken{}, store.ErrNotFound
}
func (m *memStore) validToken(hash string, now time.Time) int {
	for i, t := range m.tokens {
		if t.TokenHash == hash && t.RevokedAt == nil && t.ExpiresAt.After(now) && (t.MaxUses == 0 || t.Uses < t.MaxUses) {
			return i
		}
	}
	return -1
}
func (m *memStore) UseEnrollToken(_ context.Context, hash string, now time.Time) (store.EnrollToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.validToken(hash, now)
	if i < 0 {
		return store.EnrollToken{}, store.ErrTokenInvalid
	}
	m.tokens[i].Uses++
	return m.tokens[i], nil
}
func (m *memStore) EnrollTokenByHash(_ context.Context, hash string, now time.Time) (store.EnrollToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.validToken(hash, now)
	if i < 0 {
		return store.EnrollToken{}, store.ErrTokenInvalid
	}
	return m.tokens[i], nil
}
func (m *memStore) AgentIDTaken(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[id]; ok {
		return true, nil
	}
	for _, c := range m.certs {
		if c.AgentID == id {
			return true, nil
		}
	}
	return false, nil
}
func (m *memStore) RecordAgentCert(_ context.Context, c store.AgentCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs = append(m.certs, c)
	return nil
}
func (m *memStore) AgentCertBySerial(_ context.Context, serial string) (store.AgentCert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.certs {
		if c.Serial == serial {
			return c, nil
		}
	}
	return store.AgentCert{}, store.ErrNotFound
}
func (m *memStore) OrphanAgentCerts(_ context.Context, now time.Time) ([]store.AgentCert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AgentCert
	for _, c := range m.certs {
		if _, listed := m.agents[c.AgentID]; !listed && c.RevokedAt == nil && c.NotAfter.After(now) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *memStore) RevokeAgentCerts(_ context.Context, agentID, reason string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	now := m.now()
	for i, c := range m.certs {
		if c.AgentID == agentID && c.RevokedAt == nil {
			m.certs[i].RevokedAt, m.certs[i].RevokeReason = &now, reason
			out = append(out, c.Serial)
		}
	}
	return out, nil
}

// ---- pomocnicze ----

func testSigner(t *testing.T) *enroll.Signer {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Agents CA"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	return &enroll.Signer{CA: ca, Key: key, Validity: enroll.DefaultValidity}
}

func newCSR(t *testing.T) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func newEnrollEnv(t *testing.T) (*env, *[]string) {
	e := newEnv(t)
	dir := t.TempDir()
	exe, ca := filepath.Join(dir, "vardr-agent.exe"), filepath.Join(dir, "ca.crt")
	os.WriteFile(exe, []byte("MZ-program-agenta"), 0o644)
	os.WriteFile(filepath.Join(dir, "vardr-agent-linux-amd64"), []byte("ELF-program-agenta"), 0o644)
	os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"), 0o644)
	var revoked []string
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Enroll: &Enrollment{
		Signer: testSigner(t), AgentExe: exe, RootCA: ca, PublicServer: "192.168.88.98",
		Revoke: func(_ context.Context, serials []string, _ string) error {
			revoked = append(revoked, serials...)
			return nil
		},
	}}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.agentDir = dir
	e.addUser("admin", store.RoleAdmin, "haslo-admina-123", false)
	return e, &revoked
}

// agentPost wysyła żądanie agenta (bez sesji), opcjonalnie z certyfikatem klienta.
func agentPost(e *env, path string, body any, cert *x509.Certificate) (int, map[string]any) {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "https://panel"+path, bytes.NewReader(b))
	r.RemoteAddr = "10.9.0.1:50000"
	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func parseCert(t *testing.T, p string) *x509.Certificate {
	b, _ := pem.Decode([]byte(p))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ---- testy ----

func TestEnrollFlow(t *testing.T) {
	e, revoked := newEnrollEnv(t)
	admin := e.client("10.0.0.1")
	admin.login("admin", "haslo-admina-123")

	code, out, _ := admin.do("POST", "/api/v1/enroll-tokens", map[string]any{"name": "Księgowość", "profile": "workstation", "valid_hours": 24, "max_uses": 2})
	if code != 201 {
		t.Fatalf("token: %d %v", code, out)
	}
	secret := out["secret"].(string)
	if !strings.HasPrefix(secret, "hdt_") {
		t.Fatalf("format tokenu: %q", secret)
	}
	// Lista nie ujawnia sekretu ani skrótu.
	_, list, res := admin.do("GET", "/api/v1/enroll-tokens", nil)
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "token_hash") {
		t.Fatal("lista tokenów ujawnia sekret")
	}
	_ = res

	// Rejestracja: CN z nazwy hosta, profil z tokenu.
	code, out = agentPost(e, "/enroll/v1/register", map[string]any{"token": secret, "csr": newCSR(t), "hostname": "KSIEG-PC02"}, nil)
	if code != 200 || out["agent_id"] != "agt-ksieg-pc02" || out["profile"] != "workstation" || out["server_address"] != "192.168.88.98" {
		t.Fatalf("rejestracja: %d %v", code, out)
	}
	cert1 := parseCert(t, out["certificate"].(string))
	if cert1.Subject.CommonName != "agt-ksieg-pc02" {
		t.Fatalf("CN: %s", cert1.Subject.CommonName)
	}

	// Ten sam host ponownie: nie przejmuje tożsamości, dostaje dopisek.
	code, out = agentPost(e, "/enroll/v1/register", map[string]any{"token": secret, "csr": newCSR(t), "hostname": "KSIEG-PC02"}, nil)
	if code != 200 || !strings.HasPrefix(out["agent_id"].(string), "agt-ksieg-pc02-") {
		t.Fatalf("drugi raz: %d %v", code, out)
	}
	// Limit 2 użyć wyczerpany.
	if code, out = agentPost(e, "/enroll/v1/register", map[string]any{"token": secret, "csr": newCSR(t), "hostname": "PC03"}, nil); code != 403 {
		t.Fatalf("po wyczerpaniu: %d %v", code, out)
	}
	// Zły token i zły CSR.
	if code, _ = agentPost(e, "/enroll/v1/register", map[string]any{"token": "hdt_" + strings.Repeat("A", 43), "csr": newCSR(t), "hostname": "X"}, nil); code != 403 {
		t.Fatalf("zły token: %d", code)
	}
	if code, _ = agentPost(e, "/enroll/v1/register", map[string]any{"token": secret, "csr": "śmieci", "hostname": "X"}, nil); code != 400 {
		t.Fatalf("zły CSR: %d", code)
	}

	// Odnowienie z ważnym certyfikatem.
	code, out = agentPost(e, "/enroll/v1/renew", map[string]any{"csr": newCSR(t)}, cert1)
	if code != 200 || out["agent_id"] != "agt-ksieg-pc02" {
		t.Fatalf("odnowienie: %d %v", code, out)
	}
	cert2 := parseCert(t, out["certificate"].(string))
	if code, _ = agentPost(e, "/enroll/v1/renew", map[string]any{"csr": newCSR(t)}, nil); code != 401 {
		t.Fatalf("odnowienie bez certyfikatu: %d", code)
	}

	// Unieważnienie agenta: oba certyfikaty, rozesłane do ingest; odnowienie odrzucone.
	code, out, _ = admin.do("POST", "/api/v1/agents/agt-ksieg-pc02/revoke", map[string]any{"reason": "kradzież laptopa"})
	if code != 200 || out["revoked"] != 2.0 || len(*revoked) != 2 {
		t.Fatalf("unieważnienie: %d %v %v", code, out, *revoked)
	}
	if code, out = agentPost(e, "/enroll/v1/renew", map[string]any{"csr": newCSR(t)}, cert2); code != 403 || out["error"] != "revoked" {
		t.Fatalf("odnowienie unieważnionego: %d %v", code, out)
	}

	acts := strings.Join(e.st.actions(), ",")
	for _, want := range []string{"enroll_token_created", "agent_enrolled", "agent_enroll_failed", "agent_cert_renewed", "agent_certs_revoked"} {
		if !strings.Contains(acts, want) {
			t.Errorf("brak w audycie: %s (%s)", want, acts)
		}
	}
}

func TestEnrollPackage(t *testing.T) {
	e, _ := newEnrollEnv(t)
	admin := e.client("10.0.0.1")
	admin.login("admin", "haslo-admina-123")
	_, out, _ := admin.do("POST", "/api/v1/enroll-tokens", map[string]any{"name": "Serwery IIS", "profile": "server", "valid_hours": 48, "max_uses": 0})
	secret := out["secret"].(string)

	b, _ := json.Marshal(map[string]string{"secret": secret})
	r := httptest.NewRequest("POST", "https://panel/api/v1/enroll-tokens/package", bytes.NewReader(b))
	r.AddCookie(admin.cookie)
	r.Header.Set(csrfHeader, admin.csrf)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "vardr-agent-serwery-iis.zip") {
		t.Fatalf("paczka: %d %v", w.Code, w.Header())
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(data)
	}
	if strings.TrimSpace(files["token.txt"]) != secret || strings.TrimSpace(files["server.txt"]) != "192.168.88.98" ||
		files["vardr-agent.exe"] != "MZ-program-agenta" || !strings.Contains(files["install.cmd"], "\r\n") {
		t.Fatalf("zawartość paczki: %v", keys(files))
	}
	for name, data := range files {
		if strings.Contains(name, ".key") || strings.Contains(data, "PRIVATE KEY") {
			t.Fatalf("paczka zawiera klucz prywatny: %s", name)
		}
	}
	// Paczka Linux: tar.gz z programem (0755), tokenem (0600) i install.sh.
	b, _ = json.Marshal(map[string]string{"secret": secret, "os": "linux"})
	r = httptest.NewRequest("POST", "https://panel/api/v1/enroll-tokens/package", bytes.NewReader(b))
	r.AddCookie(admin.cookie)
	r.Header.Set(csrfHeader, admin.csrf)
	w = httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "vardr-agent-serwery-iis-linux-amd64.tar.gz") {
		t.Fatalf("paczka linux: %d %v", w.Code, w.Header())
	}
	gz, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	lin, modes := map[string]string{}, map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		lin[h.Name], modes[h.Name] = string(data), h.Mode
	}
	const d = "vardr-agent-serwery-iis/"
	if lin[d+"vardr-agent"] != "ELF-program-agenta" || modes[d+"vardr-agent"] != 0o755 || modes[d+"install.sh"] != 0o755 ||
		modes[d+"token.txt"] != 0o600 || strings.TrimSpace(lin[d+"token.txt"]) != secret || strings.TrimSpace(lin[d+"server.txt"]) != "192.168.88.98" ||
		!strings.HasPrefix(lin[d+"install.sh"], "#!/bin/sh\n") || strings.Contains(lin[d+"install.sh"], "\r") || !strings.Contains(lin[d+"ca.crt"], "BEGIN CERTIFICATE") {
		t.Fatalf("zawartość paczki linux: %v", keys(lin))
	}
	for _, c := range []struct {
		req  map[string]string
		code int
	}{
		{map[string]string{"secret": secret, "os": "linux", "arch": "arm64"}, 503}, // brak programu w agent-dist
		{map[string]string{"secret": secret, "os": "linux", "arch": "386"}, 400},
		{map[string]string{"secret": secret, "os": "macos"}, 400},
	} {
		if code, _, _ := admin.do("POST", "/api/v1/enroll-tokens/package", c.req); code != c.code {
			t.Fatalf("%v: %d", c.req, code)
		}
	}
	// Viewer nie może pobrać paczki; unieważniony token – brak paczki.
	_, toks, _ := admin.do("GET", "/api/v1/enroll-tokens", nil)
	id := toks["tokens"].([]any)[0].(map[string]any)["id"]
	admin.do("POST", "/api/v1/enroll-tokens/"+itoa(int64(id.(float64)))+"/revoke", nil)
	if code, _, _ := admin.do("POST", "/api/v1/enroll-tokens/package", map[string]string{"secret": secret}); code != 400 {
		t.Fatalf("paczka dla unieważnionego tokenu: %d", code)
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Jeden plik MSI: adres serwera i token wpisane w miejsce wypełniaczy.
func TestEnrollMSI(t *testing.T) {
	e, _ := newEnrollEnv(t)
	admin := e.client("10.0.0.1")
	admin.login("admin", "haslo-admina-123")
	_, out, _ := admin.do("POST", "/api/v1/enroll-tokens", map[string]any{"name": "Księgowość", "profile": "workstation", "valid_hours": 24, "max_uses": 5})
	secret := out["secret"].(string)
	post := func() *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"secret": secret})
		r := httptest.NewRequest("POST", "https://panel/api/v1/enroll-tokens/msi", bytes.NewReader(b))
		r.AddCookie(admin.cookie)
		r.Header.Set(csrfHeader, admin.csrf)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		return w
	}
	if w := post(); w.Code != 503 || !strings.Contains(w.Body.String(), "no_agent_msi") {
		t.Fatalf("bez instalatora: %d %s", w.Code, w.Body.String())
	}
	msiPath := filepath.Join(e.agentDir, "vardr-agent.msi")
	base := msipatch.TestFile([]byte("x"+contract.MSIServerPlaceholder+"y"), []byte(strings.Repeat("-", 4200)+contract.MSITokenPlaceholder))
	if err := os.WriteFile(msiPath, base, 0o644); err != nil {
		t.Fatal(err)
	}
	w := post()
	if w.Code != 200 || !strings.HasSuffix(w.Header().Get("Content-Disposition"), `.msi"`) {
		t.Fatalf("instalator: %d %v", w.Code, w.Header())
	}
	body := w.Body.String()
	if len(body) != len(base) || strings.Contains(body, "VARDR_MSI_") || !strings.Contains(body, "192.168.88.98   ") || !strings.Contains(body, secret) {
		t.Fatal("wartości nie wpisane do instalatora")
	}
	// Aktualizacja: bazowy plik bez zmian; instalator, którego nie da się załatać – błąd.
	r := httptest.NewRequest("GET", "https://panel/api/v1/agent-update.msi", nil)
	r.AddCookie(admin.cookie)
	wu := httptest.NewRecorder()
	e.h.ServeHTTP(wu, r)
	if wu.Code != 200 || !bytes.Equal(wu.Body.Bytes(), base) {
		t.Fatalf("aktualizacja: %d", wu.Code)
	}
	os.WriteFile(msiPath, []byte("to nie jest MSI"), 0o644)
	if w := post(); w.Code != 503 || !strings.Contains(w.Body.String(), "msi_patch_failed") {
		t.Fatalf("zły instalator: %d %s", w.Code, w.Body.String())
	}
	if !slices.Contains(e.st.actions(), "enroll_msi_downloaded") || !slices.Contains(e.st.actions(), "agent_update_msi_downloaded") {
		t.Fatalf("audyt: %v", e.st.actions())
	}
}
