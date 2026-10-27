// SPDX-License-Identifier: AGPL-3.0-or-later

package syslog

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siem/agent/internal/source"
)

func freeAddr(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().String()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func collect(t *testing.T, out <-chan source.Record, n int) []source.Record {
	t.Helper()
	var got []source.Record
	timeout := time.After(5 * time.Second)
	for len(got) < n {
		select {
		case r := <-out:
			got = append(got, r)
		case <-timeout:
			t.Fatalf("odebrano %d z %d wiadomości: %+v", len(got), n, got)
		}
	}
	return got
}

func TestSyslogUDPAndTCP(t *testing.T) {
	udp, tcp := freeAddr(t, "udp"), freeAddr(t, "tcp")
	s := &Source{Cfg: Config{UDP: udp, TCP: tcp, MaxMessage: 60}, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan source.Record, 100)
	done := make(chan source.Position)
	go func() {
		pos, _ := s.Run(ctx, source.Position{}, out)
		done <- pos
	}()
	time.Sleep(200 * time.Millisecond)

	uc, err := net.Dial("udp", udp)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(uc, "<134>Oct  9 12:00:00 fw01 date=2026-10-09 type=traffic\n")
	m2 := "<30>1 2026-10-09T12:00:01Z router1 system - - - " + strings.Repeat("x", 100)
	fmt.Fprint(uc, m2)
	uc.Close()
	got := collect(t, out, 2)
	if got[0].Source != "syslog:udp" || got[0].Peer != "127.0.0.1" || !strings.HasPrefix(got[0].Raw, "<134>Oct") ||
		strings.HasSuffix(got[0].Raw, "\n") {
		t.Fatalf("UDP: %+v", got[0])
	}
	if len(got[1].Raw) != 60 || s.Stats.Truncated.Load() != 1 || !got[1].Truncated || got[1].OriginalSize != len(m2) || got[0].Truncated {
		t.Fatalf("przycięcie do 60 bajtów: %d %q %v %d", len(got[1].Raw), got[1].Raw, got[1].Truncated, got[1].OriginalSize)
	}
	if got[1].RecordID <= got[0].RecordID || got[0].Channel != "syslog" {
		t.Fatalf("numeracja: %d %d", got[0].RecordID, got[1].RecordID)
	}

	tc, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatal(err)
	}
	m1 := "<134>1 2026-10-09T12:00:02Z fw01 - - - - pierwsza"
	fmt.Fprintf(tc, "%d %s", len(m1), m1)                               // octet counting
	fmt.Fprint(tc, "<134>Oct  9 12:00:03 fw01 druga\r\n<134>trzecia\n") // koniec linii
	long := "<134>" + strings.Repeat("y", 200)
	fmt.Fprintf(tc, "%d %s", len(long), long) // ramka ponad limit – przycięta, ze znacznikiem
	tc.Close()
	got = collect(t, out, 4)
	if got[0].Raw != m1 || got[1].Raw != "<134>Oct  9 12:00:03 fw01 druga" || got[2].Raw != "<134>trzecia" || got[0].Source != "syslog:tcp" {
		t.Fatalf("TCP: %q %q %q", got[0].Raw, got[1].Raw, got[2].Raw)
	}
	if len(got[3].Raw) != 60 || !got[3].Truncated || got[3].OriginalSize != 205 {
		t.Fatalf("ramka TCP ponad limit: %d %v %d", len(got[3].Raw), got[3].Truncated, got[3].OriginalSize)
	}

	// Strumień samych cyfr (bez spacji) – rozłączenie zamiast rosnącego bufora.
	tc, err = net.Dial("tcp", tcp)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tc.Write([]byte(strings.Repeat("9", 4096)))
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := tc.Read(make([]byte, 1)); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("połączenie z błędną ramką powinno zostać zamknięte: %v", err)
	}
	tc.Close()
	cancel()
	if pos := <-done; !pos.Valid || pos.RecordID != got[3].RecordID {
		t.Fatalf("pozycja po zatrzymaniu: %+v", pos)
	}
}

func TestSyslogAllowList(t *testing.T) {
	udp := freeAddr(t, "udp")
	s := &Source{Cfg: Config{UDP: udp, Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan source.Record, 10)
	go func() { _, _ = s.Run(ctx, source.Position{}, out) }()
	time.Sleep(200 * time.Millisecond)
	uc, _ := net.Dial("udp", udp)
	fmt.Fprint(uc, "<134>nie z dozwolonej sieci")
	uc.Close()
	deadline := time.Now().Add(2 * time.Second)
	for s.Stats.Denied.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.Stats.Denied.Load() != 1 || len(out) != 0 {
		t.Fatalf("lista dozwolonych: odrzucone %d, przyjęte %d", s.Stats.Denied.Load(), len(out))
	}
}

// Numery rekordów po restarcie nie wracają do wcześniejszych (identyfikatory zdarzeń unikalne).
func TestSyslogRecordIDsAfterRestart(t *testing.T) {
	future := uint64(time.Now().Add(time.Hour).UnixMicro())
	udp := freeAddr(t, "udp")
	s := &Source{Cfg: Config{UDP: udp}, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan source.Record, 10)
	go func() { _, _ = s.Run(ctx, source.Position{RecordID: future, Valid: true}, out) }()
	time.Sleep(200 * time.Millisecond)
	uc, _ := net.Dial("udp", udp)
	fmt.Fprint(uc, "<134>po restarcie")
	uc.Close()
	if r := collect(t, out, 1)[0]; r.RecordID != future+1 {
		t.Fatalf("numer po zapisanej pozycji: %d, oczekiwano %d", r.RecordID, future+1)
	}
	_ = io.EOF
}

// clientCert wystawia certyfikat urządzenia (CN) podpisany przez nowe CA.
func clientCert(t *testing.T, cn string) (caPEM []byte, cert tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA urządzeń"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestSyslogTLS(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, err := SelfSigned([]string{"127.0.0.1", "kolektor.local"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "s.crt"), certPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "s.key"), keyPEM, 0o600)
	caPEM, good := clientCert(t, "fw1.firma.local")
	os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0o600)
	_, foreign := clientCert(t, "fw1.firma.local") // ten sam CN, inne CA
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)

	for _, tc := range []struct {
		name      string
		clientCA  string
		names     []string
		cert      *tls.Certificate
		delivered bool
	}{
		{"bez certyfikatu urządzenia", "", nil, nil, true},
		{"certyfikat wymagany, brak", "ca.crt", nil, nil, false},
		{"certyfikat z dobrego CA", "ca.crt", nil, &good, true},
		{"certyfikat z innego CA", "ca.crt", nil, &foreign, false},
		{"nazwa na liście", "ca.crt", []string{"FW1.firma.local"}, &good, true},
		{"nazwa spoza listy", "ca.crt", []string{"fw2.firma.local"}, &good, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := ""
			if tc.clientCA != "" {
				ca = filepath.Join(dir, tc.clientCA)
			}
			cfg, err := ServerTLS(filepath.Join(dir, "s.crt"), filepath.Join(dir, "s.key"), ca)
			if err != nil {
				t.Fatal(err)
			}
			addr := freeAddr(t, "tcp")
			s := &Source{Cfg: Config{TLS: addr, TLSConfig: cfg, ClientNames: tc.names}, Log: slog.New(slog.DiscardHandler)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := make(chan source.Record, 10)
			go s.Run(ctx, source.Position{}, out)
			var conn *tls.Conn
			for i := 0; i < 50; i++ {
				ccfg := &tls.Config{RootCAs: roots, ServerName: "kolektor.local"}
				if tc.cert != nil {
					ccfg.Certificates = []tls.Certificate{*tc.cert}
				}
				conn, err = tls.Dial("tcp", addr, ccfg)
				var oe *net.OpError
				if err == nil || !errors.As(err, &oe) || oe.Op != "dial" {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err == nil {
				fmt.Fprintf(conn, "26 <13>1 - fw1 app - - - test")
				conn.Close()
			}
			select {
			case r := <-out:
				if !tc.delivered || r.Raw != "<13>1 - fw1 app - - - test" || r.Source != "syslog:tls" {
					t.Fatalf("odebrano %+v", r)
				}
			case <-time.After(time.Second):
				if tc.delivered {
					t.Fatalf("wiadomość nie dotarła (dial: %v)", err)
				}
				if s.Stats.TLSFailed.Load() == 0 {
					t.Fatal("odrzucenie nie policzone")
				}
			}
		})
	}
}
