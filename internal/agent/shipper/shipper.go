// Package shipper wysyła paczki do serwera zgodnie z kontraktem z załącznika A.
package shipper

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"siem/internal/contract"
)

// Stats to liczniki wysyłki (do logów i późniejszego heartbeatu).
type Stats struct {
	BatchesAccepted   atomic.Int64
	EventsAccepted    atomic.Int64
	Retries           atomic.Int64
	EventsQuarantined atomic.Int64
}

// HTTPSender wysyła paczki po HTTPS. Send kończy się dopiero, gdy paczka
// została przyjęta albo odłożona do lokalnej kwarantanny; błędy przejściowe
// są ponawiane bez końca (dane czekają w dzienniku źródłowym).
type HTTPSender struct {
	Client        *http.Client
	URL           string
	QuarantineDir string
	Log           *slog.Logger
	Stats         *Stats

	MinBackoff  time.Duration // pierwsze opóźnienie ponowienia
	MaxBackoff  time.Duration // limit dla błędów przejściowych
	AuthBackoff time.Duration // limit dla 401/403 (problem z certyfikatem)
}

// NewHTTPSender tworzy nadawcę z domyślnymi parametrami ponowień.
func NewHTTPSender(client *http.Client, url, quarantineDir string, log *slog.Logger) *HTTPSender {
	return &HTTPSender{
		Client: client, URL: url, QuarantineDir: quarantineDir, Log: log, Stats: &Stats{},
		MinBackoff: time.Second, MaxBackoff: time.Minute, AuthBackoff: 5 * time.Minute,
	}
}

// Send wysyła paczkę. Zwraca błąd wyłącznie przy anulowaniu kontekstu –
// wtedy paczka NIE jest potwierdzona i zostanie wysłana ponownie po restarcie.
func (s *HTTPSender) Send(ctx context.Context, b *contract.Batch) error {
	body, err := encode(b)
	if err != nil {
		// Nie da się zserializować – ponawianie nic nie zmieni.
		s.quarantine(b, "błąd serializacji: "+err.Error())
		return nil
	}

	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			s.Stats.Retries.Add(1)
		}
		status, retryAfter, respBody, err := s.post(ctx, body)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		var wait time.Duration
		switch {
		case err != nil:
			s.Log.Warn("wysyłka nieudana, ponowię", "batch_id", b.BatchID, "attempt", attempt+1, "err", err)
			wait = backoff(s.MinBackoff, s.MaxBackoff, attempt)

		case status == http.StatusOK:
			var resp contract.Response
			if err := json.Unmarshal(respBody, &resp); err == nil &&
				resp.Status == contract.StatusAccepted && resp.BatchID == b.BatchID {
				s.Stats.BatchesAccepted.Add(1)
				s.Stats.EventsAccepted.Add(int64(len(b.Events)))
				return nil
			}
			s.Log.Warn("niepoprawne potwierdzenie serwera, ponowię", "batch_id", b.BatchID, "body", truncate(respBody))
			wait = backoff(s.MinBackoff, s.MaxBackoff, attempt)

		case status == http.StatusRequestEntityTooLarge:
			return s.split(ctx, b)

		case status == http.StatusBadRequest:
			s.quarantine(b, "serwer odrzucił paczkę (400): "+truncate(respBody))
			return nil

		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			s.Log.Error("serwer odrzucił tożsamość agenta – sprawdź certyfikat", "status", status, "body", truncate(respBody))
			wait = backoff(s.MinBackoff*10, s.AuthBackoff, attempt)

		case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
			wait = retryAfter
			if wait <= 0 {
				wait = backoff(s.MinBackoff, s.MaxBackoff, attempt)
			}
			s.Log.Info("serwer przeciążony, czekam", "status", status, "wait", wait)

		default:
			s.Log.Warn("błąd serwera, ponowię", "status", status, "attempt", attempt+1, "body", truncate(respBody))
			wait = backoff(s.MinBackoff, s.MaxBackoff, attempt)
		}

		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func (s *HTTPSender) post(ctx context.Context, body []byte) (status int, retryAfter time.Duration, respBody []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return 0, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if v := resp.Header.Get("Retry-After"); v != "" {
		if sec, err := strconv.Atoi(v); err == nil && sec >= 0 {
			retryAfter = time.Duration(sec) * time.Second
		}
	}
	return resp.StatusCode, retryAfter, respBody, nil
}

// split dzieli zbyt dużą paczkę na pół i wysyła części jako nowe paczki.
func (s *HTTPSender) split(ctx context.Context, b *contract.Batch) error {
	if len(b.Events) <= 1 {
		s.quarantine(b, "pojedyncze zdarzenie przekracza limit rozmiaru serwera (413)")
		return nil
	}
	mid := len(b.Events) / 2
	s.Log.Info("paczka za duża, dzielę", "batch_id", b.BatchID, "events", len(b.Events))
	for _, part := range [][]contract.Event{b.Events[:mid], b.Events[mid:]} {
		nb := *b
		nb.BatchID = contract.NewBatchID()
		nb.Events = part
		if err := s.Send(ctx, &nb); err != nil {
			return err
		}
	}
	return nil
}

// quarantine zapisuje odrzuconą paczkę lokalnie, żeby nie zniknęła bez śladu.
func (s *HTTPSender) quarantine(b *contract.Batch, reason string) {
	s.Stats.EventsQuarantined.Add(int64(len(b.Events)))
	s.Log.Error("paczka przeniesiona do lokalnej kwarantanny", "batch_id", b.BatchID, "events", len(b.Events), "reason", reason)
	if s.QuarantineDir == "" {
		return
	}
	if err := os.MkdirAll(s.QuarantineDir, 0o700); err != nil {
		s.Log.Error("nie można utworzyć katalogu kwarantanny", "err", err)
		return
	}
	data, _ := json.Marshal(struct {
		Reason string          `json:"reason"`
		Batch  *contract.Batch `json:"batch"`
	}{reason, b})
	p := filepath.Join(s.QuarantineDir, "batch-"+b.BatchID+".json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		s.Log.Error("nie można zapisać kwarantanny", "path", p, "err", err)
	}
}

func encode(b *contract.Batch) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// backoff zwraca opóźnienie wykładnicze z losowym rozproszeniem (połowa–całość).
func backoff(min, max time.Duration, attempt int) time.Duration {
	d := min
	for i := 0; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func truncate(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "…"
	}
	return string(b)
}

// NewTLSClient tworzy klienta HTTPS z mTLS (TLS 1.3) i zwraca identyfikator
// agenta odczytany z pola CN certyfikatu – tożsamość agenta wynika z
// certyfikatu, a nie z konfiguracji.
func NewTLSClient(caFile, certFile, keyFile string, timeout time.Duration) (*http.Client, string, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, "", fmt.Errorf("CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, "", errors.New("CA: brak poprawnego certyfikatu PEM")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, "", fmt.Errorf("certyfikat agenta: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, "", fmt.Errorf("certyfikat agenta: %w", err)
	}
	agentID := leaf.Subject.CommonName
	if agentID == "" {
		return nil, "", errors.New("certyfikat agenta nie zawiera CN (identyfikatora agenta)")
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, "", fmt.Errorf("certyfikat agenta wygasł %s", leaf.NotAfter.Format(time.RFC3339))
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}
	tr.Proxy = nil // ruch agenta nie powinien przechodzić przez proxy systemowe
	return &http.Client{Transport: tr, Timeout: timeout}, agentID, nil
}
