// Package enroll wystawia certyfikaty agentom rejestrowanym tokenem
// (Bifröst, roadmapa załącznik C). Agent generuje klucz u siebie i przysyła
// tylko prośbę o certyfikat (CSR) – klucz prywatny nigdy nie opuszcza
// komputera. Podpisuje CA agentów (tylko certyfikaty klientów).
package enroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// DefaultValidity to ważność certyfikatu agenta; agent odnawia go sam,
// gdy do końca zostaje mniej niż RenewBefore.
const (
	DefaultValidity = 90 * 24 * time.Hour
	RenewBefore     = 30 * 24 * time.Hour
)

// Signer podpisuje certyfikaty agentów.
type Signer struct {
	CA       *x509.Certificate
	Key      crypto.Signer
	Validity time.Duration
}

// LoadSigner wczytuje CA agentów (agents-ca.crt / agents-ca.key z siem-pki).
func LoadSigner(certFile, keyFile string) (*Signer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("niepoprawne pliki CA agentów (PEM)")
	}
	ca, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("klucz CA agentów: %w", err)
	}
	if !ca.IsCA {
		return nil, errors.New("certyfikat CA agentów nie jest urzędem certyfikacji")
	}
	return &Signer{CA: ca, Key: key, Validity: DefaultValidity}, nil
}

// ParseCSR dekoduje i sprawdza prośbę o certyfikat: poprawny podpis
// (agent posiada klucz) i bezpieczny typ klucza.
func ParseCSR(pemData string) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode([]byte(pemData))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("oczekiwano CSR w formacie PEM")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("podpis CSR: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, errors.New("dozwolone krzywe ECDSA: P-256, P-384")
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("klucz RSA musi mieć co najmniej 2048 bitów")
		}
	default:
		return nil, errors.New("nieobsługiwany typ klucza (dozwolone ECDSA P-256/P-384 i RSA ≥ 2048)")
	}
	return csr, nil
}

// Issued to wystawiony certyfikat.
type Issued struct {
	PEM      string
	Serial   string // szesnastkowo, małe litery (jak w heartbeacie)
	NotAfter time.Time
}

// Sign wystawia certyfikat klienta dla agenta. Treść CSR (np. podany
// w nim CN) jest ignorowana – tożsamość nadaje serwer.
func (s *Signer) Sign(csr *x509.CertificateRequest, agentID string, now time.Time) (Issued, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return Issued{}, err
	}
	notAfter := now.Add(s.Validity)
	if notAfter.After(s.CA.NotAfter) {
		notAfter = s.CA.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"Vardr Agents"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.CA, csr.PublicKey, s.Key)
	if err != nil {
		return Issued{}, err
	}
	return Issued{
		PEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Serial:   serial.Text(16),
		NotAfter: notAfter,
	}, nil
}

// AgentIDFor proponuje identyfikator agenta z nazwy hosta: "agt-" + nazwa
// małymi literami (litery, cyfry, myślnik), maks. 40 znaków nazwy.
func AgentIDFor(hostname string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(hostname) {
		if b.Len() >= 40 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		return "agt-" + RandomSuffix()
	}
	return "agt-" + name
}

// RandomSuffix to krótki losowy dopisek odróżniający identyfikatory.
func RandomSuffix() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
