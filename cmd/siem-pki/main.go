// Command siem-pki tworzy laboratoryjną infrastrukturę certyfikatów dla mTLS:
// urząd certyfikacji (CA), certyfikat serwera i certyfikaty agentów.
//
// To narzędzie WYŁĄCZNIE do laboratorium. W docelowym systemie agenci
// otrzymują certyfikaty w procesie rejestracji tokenem (roadmapa, etap 2).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func usage() {
	fmt.Fprint(os.Stderr, `siem-pki – certyfikaty laboratoryjne dla mTLS

Użycie:
  siem-pki ca     [-out certs]                                  nowy urząd certyfikacji
  siem-pki server [-out certs] [-hosts localhost,127.0.0.1]     certyfikat serwera
  siem-pki agent  [-out certs] [-id agt-...] [-name agent]      certyfikat agenta (CN = identyfikator agenta)
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	out := fs.String("out", "certs", "katalog wyjściowy")
	hosts := fs.String("hosts", "localhost,127.0.0.1", "nazwy DNS i adresy IP serwera (po przecinku)")
	id := fs.String("id", "", "identyfikator agenta (domyślnie losowy agt-...)")
	name := fs.String("name", "agent", "prefiks nazw plików certyfikatu agenta")
	_ = fs.Parse(os.Args[2:])

	var err error
	switch os.Args[1] {
	case "ca":
		err = makeCA(*out)
	case "server":
		err = makeServer(*out, strings.Split(*hosts, ","))
	case "agent":
		agentID := *id
		if agentID == "" {
			agentID = randomAgentID()
		}
		err = makeAgent(*out, *name, agentID)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "błąd:", err)
		os.Exit(1)
	}
}

func randomAgentID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "agt-" + hex.EncodeToString(b)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func makeCA(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); err == nil {
		return errors.New("CA już istnieje w " + dir + " – usuń ją ręcznie, jeśli naprawdę chcesz nową")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "SIEM Lab CA", Organization: []string{"SIEM Lab"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := write(dir, "ca", der, key); err != nil {
		return err
	}
	fmt.Println("Utworzono CA:", filepath.Join(dir, "ca.crt"))
	return nil
}

func loadCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, nil, fmt.Errorf("brak CA (uruchom najpierw: siem-pki ca): %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("uszkodzone pliki CA")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func issue(dir, name string, tmpl *x509.Certificate) error {
	ca, caKey, err := loadCA(dir)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl.SerialNumber = serial()
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	return write(dir, name, der, key)
}

func makeServer(dir string, hosts []string) error {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "siem-server", Organization: []string{"SIEM Lab"}},
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if err := issue(dir, "server", tmpl); err != nil {
		return err
	}
	fmt.Printf("Utworzono certyfikat serwera dla %v\n", hosts)
	return nil
}

func makeAgent(dir, name, agentID string) error {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: agentID, Organization: []string{"SIEM Lab Agents"}},
		NotAfter:    time.Now().AddDate(0, 3, 0), // krótko żyjące certyfikaty agentów
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := issue(dir, name, tmpl); err != nil {
		return err
	}
	fmt.Printf("Utworzono certyfikat agenta %s: %s.crt / %s.key\n", agentID, filepath.Join(dir, name), filepath.Join(dir, name))
	return nil
}

func write(dir, name string, der []byte, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".key"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}
