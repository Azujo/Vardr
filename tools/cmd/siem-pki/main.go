// SPDX-License-Identifier: AGPL-3.0-or-later

// Command siem-pki tworzy infrastrukturę certyfikatów dla mTLS: urząd
// certyfikacji (CA), certyfikat serwera, CA rejestracji agentów i – tylko
// w laboratorium – certyfikaty agentów. Używa go install.sh przy instalacji
// serwera; agenci otrzymują certyfikaty przy rejestracji tokenem.
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
  siem-pki agents-ca [-out certs]                               CA agentów (online, tylko certyfikaty klientów;
                                                               używane przez panel do rejestracji tokenem)
  siem-pki agent  [-out certs] [-id agt-...] [-name agent]      certyfikat agenta (CN = identyfikator agenta)
  siem-pki package -id agt-pc01 [-server 192.168.88.98] [-agent bin/vardr-agent.exe] [-out dist] [-ca-dir certs]
                                                               paczka instalacyjna agenta dla jednego komputera
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
	caDir := fs.String("ca-dir", "certs", "package: katalog z CA")
	agentExe := fs.String("agent", filepath.Join("bin", "vardr-agent.exe"), "package: plik programu agenta")
	server := fs.String("server", "", "package: domyślny adres serwera zapisany w paczce")
	_ = fs.Parse(os.Args[2:])

	var err error
	switch os.Args[1] {
	case "ca":
		err = makeCA(*out)
	case "server":
		err = makeServer(*out, strings.Split(*hosts, ","))
	case "agents-ca":
		err = makeAgentsCA(*out)
	case "agent":
		agentID := *id
		if agentID == "" {
			agentID = randomAgentID()
		}
		err = makeAgent(*out, *name, agentID)
	case "package":
		if *id == "" {
			fmt.Fprintln(os.Stderr, "błąd: podaj -id, np. -id agt-pc01 (identyfikator widoczny w SIEM)")
			os.Exit(2)
		}
		outDir := *out
		if outDir == "certs" { // domyślny -out dla paczek
			outDir = "dist"
		}
		err = makePackage(*caDir, filepath.Join(outDir, *id), *id, *agentExe, *server)
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
		Subject:               pkix.Name{CommonName: "Vardr CA", Organization: []string{"Vardr"}},
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
	return issueTo(dir, dir, name, tmpl)
}

// issueTo podpisuje certyfikat CA z caDir i zapisuje go w outDir.
func issueTo(caDir, outDir, name string, tmpl *x509.Certificate) error {
	ca, caKey, err := loadCA(caDir)
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
	return write(outDir, name, der, key)
}

func makeServer(dir string, hosts []string) error {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "siem-server", Organization: []string{"Vardr"}},
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

func agentTemplate(agentID string) *x509.Certificate {
	return &x509.Certificate{
		Subject:     pkix.Name{CommonName: agentID, Organization: []string{"Vardr Agents"}},
		NotAfter:    time.Now().AddDate(0, 3, 0), // krótko żyjące certyfikaty agentów
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func makeAgent(dir, name, agentID string) error {
	if err := issue(dir, name, agentTemplate(agentID)); err != nil {
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

// makePackage tworzy folder z wszystkim, czego potrzeba do instalacji
// agenta na jednym komputerze: program, CA, certyfikat i klucz agenta,
// opcjonalnie domyślny adres serwera i instrukcję.
func makePackage(caDir, outDir, agentID, agentExe, server string) error {
	if _, err := os.Stat(outDir); err == nil {
		return fmt.Errorf("%s już istnieje – usuń go lub wybierz inny -id", outDir)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	if err := issueTo(caDir, outDir, "agent", agentTemplate(agentID)); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(caDir, "ca.crt"), filepath.Join(outDir, "ca.crt")); err != nil {
		return err
	}
	if err := copyFile(agentExe, filepath.Join(outDir, "vardr-agent.exe")); err != nil {
		return fmt.Errorf("program agenta (%s): %w – zbuduj go: go build -o bin/vardr-agent.exe ./cmd/vardr-agent", agentExe, err)
	}
	if server != "" {
		if err := os.WriteFile(filepath.Join(outDir, "server.txt"), []byte(server+"\r\n"), 0o644); err != nil {
			return err
		}
	}
	serverArg := " -server <adres serwera>"
	if server != "" {
		serverArg = ""
	}
	instr := strings.ReplaceAll(fmt.Sprintf(`Paczka instalacyjna agenta SIEM: %s

Zawartość:
  vardr-agent.exe   program agenta
  ca.crt           certyfikat urzędu (weryfikacja serwera)
  agent.crt        certyfikat tego agenta
  agent.key        klucz prywatny agenta - TAJNY, nie udostępniaj
  server.txt       domyślny adres serwera (jeśli został podany)

Instalacja (PowerShell lub cmd uruchomione JAKO ADMINISTRATOR, w tym folderze):
  .\vardr-agent.exe install%s

Po instalacji (nowe okno, jako administrator):
  vardr-agent status
  vardr-agent stop | start | restart
  vardr-agent test
  vardr-agent set-server <adres>

Po instalacji usuń ten folder - kopia klucza jest już w C:\ProgramData\SiemAgent\certs.
`, agentID, serverArg), "\n", "\r\n")
	if err := os.WriteFile(filepath.Join(outDir, "INSTRUKCJA.txt"), []byte(instr), 0o644); err != nil {
		return err
	}
	fmt.Printf("Utworzono paczkę %s (agent %s)\n", outDir, agentID)
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// makeAgentsCA tworzy osobny urząd dla certyfikatów agentów. Jego klucz
// leży na serwerze (panel podpisuje nim certyfikaty przy rejestracji
// tokenem), dlatego może wystawiać WYŁĄCZNIE certyfikaty klientów
// (ExtKeyUsage = ClientAuth). Główne CA (ca.key) zostaje offline – agenci
// sprawdzają nim serwer, więc wyciek klucza CA agentów nie pozwala podszyć
// się pod serwer.
func makeAgentsCA(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "agents-ca.key")); err == nil {
		return errors.New("CA agentów już istnieje w " + dir + " – usuń ją ręcznie, jeśli naprawdę chcesz nową")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Vardr Agents CA", Organization: []string{"Vardr"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := write(dir, "agents-ca", der, key); err != nil {
		return err
	}
	fmt.Println("Utworzono CA agentów:", filepath.Join(dir, "agents-ca.crt"))
	fmt.Println("Klucz agents-ca.key skopiuj na serwer (katalog certs stosu) – używa go panel do rejestracji agentów.")
	return nil
}
