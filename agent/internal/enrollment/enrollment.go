// Package enrollment to strona agenta rejestracji tokenem (Bifröst):
// agent generuje klucz prywatny u siebie, wysyła do panelu tylko prośbę
// o certyfikat (CSR) i odnawia certyfikat przed wygaśnięciem.
package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Ścieżki endpointów panelu (siem-api).
const (
	RegisterPath = "/enroll/v1/register"
	RenewPath    = "/enroll/v1/renew"
	// PanelPort to domyślny port panelu (rejestracja i odnowienia).
	PanelPort = "8444"
)

// PanelURL wyznacza adres panelu z adresu endpointu zdarzeń agenta
// (ten sam host, port panelu), np. https://10.0.0.5:8443/v1/ingest →
// https://10.0.0.5:8444.
func PanelURL(ingestURL string) (string, error) {
	u, err := url.Parse(ingestURL)
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("brak nazwy hosta w %q", ingestURL)
	}
	return "https://" + net.JoinHostPort(u.Hostname(), PanelPort), nil
}

// Result to odpowiedź panelu.
type Result struct {
	AgentID       string    `json:"agent_id"`
	Certificate   string    `json:"certificate"`
	NotAfter      time.Time `json:"not_after"`
	Profile       string    `json:"profile"`
	RenewBeforeS  int       `json:"renew_before_s"`
	ServerAddress string    `json:"server_address"`
}

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// newKeyAndCSR generuje klucz ECDSA P-256 i prośbę o certyfikat.
func newKeyAndCSR() (keyPEM []byte, csrPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "vardr-agent"}, // tożsamość nadaje serwer
	}, key)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func post(ctx context.Context, client *http.Client, u string, body any) (Result, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		var ae apiError
		if json.Unmarshal(raw, &ae) == nil && ae.Message != "" {
			return Result{}, fmt.Errorf("panel odrzucił żądanie (HTTP %d): %s", resp.StatusCode, ae.Message)
		}
		return Result{}, fmt.Errorf("panel odrzucił żądanie (HTTP %d)", resp.StatusCode)
	}
	var res Result
	if err := json.Unmarshal(raw, &res); err != nil {
		return Result{}, fmt.Errorf("niepoprawna odpowiedź panelu: %w", err)
	}
	if err := checkCert(res); err != nil {
		return Result{}, err
	}
	return res, nil
}

func checkCert(res Result) error {
	b, _ := pem.Decode([]byte(res.Certificate))
	if b == nil {
		return errors.New("panel nie zwrócił certyfikatu")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	if cert.Subject.CommonName != res.AgentID || res.AgentID == "" {
		return errors.New("certyfikat nie pasuje do nadanego identyfikatora agenta")
	}
	return nil
}

// Info to dane komputera przekazywane przy rejestracji.
type Info struct {
	Hostname, OS, Version string
}

// Register rejestruje agenta tokenem. rootCA weryfikuje certyfikat panelu
// (na tym etapie agent nie ma jeszcze certyfikatu klienta).
func Register(ctx context.Context, panelURL string, rootCA *x509.CertPool, token string, info Info) (Result, []byte, error) {
	keyPEM, csr, err := newKeyAndCSR()
	if err != nil {
		return Result{}, nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCA},
		Proxy:           nil,
	}}
	res, err := post(ctx, client, panelURL+RegisterPath, map[string]string{
		"token": token, "csr": csr, "hostname": info.Hostname, "os": info.OS, "version": info.Version,
	})
	return res, keyPEM, err
}

// Renew prosi o nowy certyfikat (z nowym kluczem), uwierzytelniając się
// obecnym certyfikatem – klient musi mieć certyfikat agenta (mTLS).
func Renew(ctx context.Context, client *http.Client, panelURL string) (Result, []byte, error) {
	keyPEM, csr, err := newKeyAndCSR()
	if err != nil {
		return Result{}, nil, err
	}
	res, err := post(ctx, client, panelURL+RenewPath, map[string]string{"csr": csr})
	return res, keyPEM, err
}

// WritePair zapisuje klucz i certyfikat. Najpierw oba pliki tymczasowe,
// potem podmiana – przerwanie w połowie nie zostawia pary niepasujących plików
// (najwyżej stary klucz z nowym certyfikatem przez ułamek sekundy).
func WritePair(certFile, keyFile string, certPEM, keyPEM []byte) error {
	if err := os.WriteFile(keyFile+".new", keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certFile+".new", certPEM, 0o644); err != nil {
		return err
	}
	if err := os.Rename(keyFile+".new", keyFile); err != nil {
		return err
	}
	return os.Rename(certFile+".new", certFile)
}

// Holder to bieżący certyfikat agenta (shipper.CertHolder).
type Holder interface {
	Leaf() *x509.Certificate
	Reload(certFile, keyFile string) error
}

// Renewer odnawia certyfikat, gdy do końca ważności zostaje mniej niż Before.
type Renewer struct {
	Client   *http.Client // klient mTLS agenta
	PanelURL string
	CertFile string
	KeyFile  string
	Holder   Holder
	Log      *slog.Logger
	Warn     func(string) // opcjonalnie: ostrzeżenie w statusie agenta

	Before time.Duration // domyślnie 30 dni
	Every  time.Duration // domyślnie co 6 h
}

// Run sprawdza ważność certyfikatu do zakończenia ctx.
func (r *Renewer) Run(ctx context.Context) {
	if r.Before <= 0 {
		r.Before = 30 * 24 * time.Hour
	}
	if r.Every <= 0 {
		r.Every = 6 * time.Hour
	}
	wait := time.Minute
	warned := false
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		wait = r.Every
		left := time.Until(r.Holder.Leaf().NotAfter)
		if left > r.Before {
			continue
		}
		if err := r.RenewNow(ctx); err != nil {
			wait = time.Hour // ponawiamy częściej, gdy termin się zbliża
			msg := fmt.Sprintf("odnowienie certyfikatu agenta nieudane (ważny jeszcze %d dni): %v", int(left.Hours()/24), err)
			r.Log.Warn(msg, "eventlog", true)
			if r.Warn != nil && (!warned || left < 7*24*time.Hour) {
				r.Warn(msg)
				warned = true
			}
			continue
		}
		warned = false
	}
}

// RenewNow odnawia certyfikat od razu.
func (r *Renewer) RenewNow(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	res, keyPEM, err := Renew(ctx, r.Client, r.PanelURL)
	if err != nil {
		return err
	}
	if err := WritePair(r.CertFile, r.KeyFile, []byte(res.Certificate), keyPEM); err != nil {
		return err
	}
	if err := r.Holder.Reload(r.CertFile, r.KeyFile); err != nil {
		return err
	}
	r.Log.Info("certyfikat agenta odnowiony", "not_after", res.NotAfter.Format(time.DateOnly), "eventlog", true)
	return nil
}
