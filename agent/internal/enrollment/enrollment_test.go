// SPDX-License-Identifier: AGPL-3.0-or-later

package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siem/agent/internal/shipper"
)

// fakePanel podpisuje CSR własnym CA (jak siem-api) i sprawdza token.
type fakePanel struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	valid time.Duration
}

func newFakePanel(t *testing.T) *fakePanel {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	return &fakePanel{ca: ca, caKey: key, valid: 90 * 24 * time.Hour}
}

func (p *fakePanel) sign(t *testing.T, csrPEM, cn string) string {
	b, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR: %v", err)
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(p.valid),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		p.ca, csr.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (p *fakePanel) server(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+RegisterPath, func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		if req["token"] != "hdt_dobry" {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"error": "bad_token", "message": "token rejestracyjny jest nieważny"})
			return
		}
		json.NewEncoder(w).Encode(Result{AgentID: "agt-pc01", Certificate: p.sign(t, req["csr"], "agt-pc01"),
			Profile: "workstation", ServerAddress: "10.0.0.5"})
	})
	mux.HandleFunc("POST "+RenewPath, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(401)
			return
		}
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		json.NewEncoder(w).Encode(Result{AgentID: cn, Certificate: p.sign(t, req["csr"], cn)})
	})
	srv := httptest.NewUnstartedServer(mux)
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	srv.StartTLS()
	return srv
}

func TestPanelURL(t *testing.T) {
	got, err := PanelURL("https://siem.firma.local:8443/v1/ingest")
	if err != nil || got != "https://siem.firma.local:8444" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestRegisterAndRenew(t *testing.T) {
	p := newFakePanel(t)
	srv := p.server(t)
	defer srv.Close()
	// Agent ufa certyfikatowi testowego serwera (zamiast głównego CA).
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	if _, _, err := Register(t.Context(), srv.URL, roots, "hdt_zly", Info{Hostname: "PC01"}); err == nil ||
		!strings.Contains(err.Error(), "token rejestracyjny jest nieważny") {
		t.Fatalf("zły token: %v", err)
	}
	res, keyPEM, err := Register(t.Context(), srv.URL, roots, "hdt_dobry", Info{Hostname: "PC01", Version: "0.5.0"})
	if err != nil || res.AgentID != "agt-pc01" || res.Profile != "workstation" {
		t.Fatalf("rejestracja: %+v %v", res, err)
	}
	dir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(dir, "agent.crt"), filepath.Join(dir, "agent.key"), filepath.Join(dir, "ca.crt")
	if err := WritePair(certFile, keyFile, []byte(res.Certificate), keyPEM); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644)

	// Odnowienie z mTLS i podmiana certyfikatu bez restartu.
	client, holder, err := shipper.NewReloadableTLSClient(caFile, certFile, keyFile, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	before := holder.Leaf().SerialNumber
	r := &Renewer{Client: client, PanelURL: srv.URL, CertFile: certFile, KeyFile: keyFile, Holder: holder,
		Log: slog.New(slog.DiscardHandler)}
	if err := r.RenewNow(t.Context()); err != nil {
		t.Fatalf("odnowienie: %v", err)
	}
	if holder.Leaf().SerialNumber.Cmp(before) == 0 || holder.AgentID() != "agt-pc01" {
		t.Fatal("certyfikat nie został podmieniony")
	}
	if _, err := os.Stat(keyFile + ".new"); !os.IsNotExist(err) {
		t.Fatal("zostały pliki tymczasowe")
	}
}
