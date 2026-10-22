// SPDX-License-Identifier: AGPL-3.0-or-later

package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Agents CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &Signer{CA: ca, Key: key, Validity: DefaultValidity}
}

func csrPEM(t *testing.T, key any, cn string) string {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestSignClientCertificate(t *testing.T) {
	s := testSigner(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := ParseCSR(csrPEM(t, key, "agt-podszyty-admin"))
	if err != nil {
		t.Fatal(err)
	}
	iss, err := s.Sign(csr, "agt-pc01", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(iss.PEM))
	cert, _ := x509.ParseCertificate(b.Bytes)
	if cert.Subject.CommonName != "agt-pc01" {
		t.Fatalf("CN z CSR nie może decydować o tożsamości: %s", cert.Subject.CommonName)
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.CA)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("weryfikacja jako klient: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("certyfikat agenta nie może działać jako certyfikat serwera")
	}
	if cert.SerialNumber.Text(16) != iss.Serial || time.Until(iss.NotAfter) < 89*24*time.Hour {
		t.Fatalf("serial %s / ważność %v", iss.Serial, iss.NotAfter)
	}
}

func TestParseCSRRejects(t *testing.T) {
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := ParseCSR(csrPEM(t, weak, "x")); err == nil {
		t.Error("RSA 1024 powinien zostać odrzucony")
	}
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if _, err := ParseCSR(csrPEM(t, p224, "x")); err == nil {
		t.Error("P-224 powinna zostać odrzucona")
	}
	good, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	block, _ := pem.Decode([]byte(csrPEM(t, good, "x")))
	block.Bytes[len(block.Bytes)-5] ^= 0xff // uszkodzony podpis
	if _, err := ParseCSR(string(pem.EncodeToMemory(block))); err == nil {
		t.Error("uszkodzony CSR powinien zostać odrzucony")
	}
	if _, err := ParseCSR("nie pem"); err == nil {
		t.Error("śmieci powinny zostać odrzucone")
	}
}

func TestAgentIDFor(t *testing.T) {
	for in, want := range map[string]string{
		"KSIEG-PC02":            "agt-ksieg-pc02",
		"dc01.lab.local":        "agt-dc01-lab-local",
		"Żółw PC":               "agt-wpc",
		strings.Repeat("a", 80): "agt-" + strings.Repeat("a", 40),
	} {
		if got := AgentIDFor(in); got != want {
			t.Errorf("%q → %q, chcę %q", in, got, want)
		}
	}
	if got := AgentIDFor("!!!"); !strings.HasPrefix(got, "agt-") || len(got) != 10 {
		t.Errorf("pusta nazwa → %q", got)
	}
}
