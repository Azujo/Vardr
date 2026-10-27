// SPDX-License-Identifier: AGPL-3.0-or-later

package syslog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// ServerTLS buduje konfigurację TLS odbioru syslog: certyfikat kolektora
// i – gdy podano clientCA – wymagany certyfikat urządzenia wystawiony przez
// to CA (uwierzytelnienie nadawcy, którego syslog sam nie ma).
func ServerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("syslog TLS certificate: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("syslog TLS client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("syslog TLS client CA: no certificate in " + clientCAFile)
		}
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// SelfSigned tworzy samopodpisany certyfikat kolektora (ECDSA P-256) dla
// podanych nazw i adresów IP. Urządzenia ufają mu przez wpisanie samego
// certyfikatu jako CA (np. rsyslog: DefaultNetstreamDriverCAFile).
func SelfSigned(hosts []string, days int) (certPEM, keyPEM []byte, err error) {
	if len(hosts) == 0 {
		return nil, nil, errors.New("give at least one name or IP address of the collector")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"Vardr syslog collector"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Certyfikat jest też własnym CA (urządzenia wskazują go jako zaufany).
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), nil
}
