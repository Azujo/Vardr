// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
)

type harness struct {
	u        *Updater
	status   chan Status
	installs chan string
	result   chan error // wynik instalatora (wait)
	cancel   context.CancelFunc
}

func newHarness(t *testing.T, msi []byte) *harness {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != contract.AgentMSIPath {
			http.NotFound(w, r)
			return
		}
		w.Write(msi)
	}))
	t.Cleanup(srv.Close)
	h := &harness{status: make(chan Status, 16), installs: make(chan string, 4), result: make(chan error, 4)}
	h.u = &Updater{Client: srv.Client(), PanelURL: srv.URL, Dir: t.TempDir(), Version: "0.9.0",
		Log: slog.New(slog.DiscardHandler), Report: func(s Status) { h.status <- s }}
	h.u.install = func(msi, _ string) (func() error, error) {
		h.installs <- msi
		return func() error { return <-h.result }, nil
	}
	return h
}

func (h *harness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go h.u.Run(ctx)
}

func (h *harness) waitState(t *testing.T, state string) Status {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case s := <-h.status:
			if s.State == state {
				return s
			}
		case <-timeout:
			t.Fatalf("brak stanu %s", state)
		}
	}
}

func offer(data []byte, version string) *contract.AgentUpdate {
	sum := sha256.Sum256(data)
	return &contract.AgentUpdate{Version: version, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func TestUpdateInstallsAndRetries(t *testing.T) {
	msi := []byte("instalator")
	h := newHarness(t, msi)
	h.start()
	defer h.cancel()

	// Starsza albo ta sama wersja – nic się nie dzieje.
	h.u.Offer(offer(msi, "0.9.0"))
	h.u.Offer(offer(msi, "0.10.0"))
	var path string
	select {
	case path = <-h.installs:
	case <-time.After(5 * time.Second):
		t.Fatal("instalator nie uruchomiony")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "instalator" || !strings.HasSuffix(path, "vardr-agent-0.10.0.msi") {
		t.Fatalf("instalator: %q %v %s", data, err, path)
	}
	a, err := h.u.loadAttempt()
	if err != nil || a.Version != "0.10.0" || a.From != "0.9.0" {
		t.Fatalf("zapis próby: %+v %v", a, err)
	}

	// Agent działa dalej po końcu instalatora – próba nieudana, ponowienie za Retry.
	h.result <- errors.New("exit status 1603")
	s := h.waitState(t, StateFailed)
	if !strings.Contains(s.Error, "1603") {
		t.Fatalf("błąd: %+v", s)
	}
	if w := h.u.retryWait(offer(msi, "0.10.0")); w < 5*time.Hour {
		t.Fatalf("ponowienie za %v", w)
	}
	select {
	case <-h.installs:
		t.Fatal("ponowna instalacja przed upływem Retry")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestUpdateRejectsBadSum(t *testing.T) {
	h := newHarness(t, []byte("podmieniony instalator"))
	h.start()
	defer h.cancel()
	h.u.Offer(offer([]byte("instalator"), "0.10.0"))
	s := h.waitState(t, StateFailed)
	if !strings.Contains(s.Error, "SHA-256") {
		t.Fatalf("błąd: %+v", s)
	}
	if len(h.installs) != 0 {
		t.Fatal("uruchomiono instalator z niezgodną sumą")
	}
	if _, err := os.Stat(h.u.msiPath("0.10.0")); err == nil {
		t.Fatal("niezgodny instalator został na dysku")
	}
}

func TestUpdateAfterRestart(t *testing.T) {
	// Nowa wersja po starcie: próba zakończona powodzeniem, pliki usunięte.
	h := newHarness(t, nil)
	h.u.init()
	os.MkdirAll(h.u.dir(), 0o700)
	os.WriteFile(h.u.msiPath("0.10.0"), []byte("x"), 0o600)
	h.u.saveAttempt(attempt{Version: "0.10.0", From: "0.9.0", AttemptedAt: time.Now()})
	h.u.Version = "0.10.0"
	h.start()
	s := h.waitState(t, StateDone)
	h.cancel()
	if s.From != "0.9.0" || s.Target != "0.10.0" {
		t.Fatalf("stan: %+v", s)
	}
	if _, err := os.Stat(filepath.Join(h.u.Dir, stateFile)); err == nil {
		t.Fatal("update.json nie usunięty")
	}
	if _, err := os.Stat(h.u.dir()); err == nil {
		t.Fatal("katalog instalatora nie usunięty")
	}

	// Stara wersja po starcie: próba nieudana (zgłoszona z dziennikiem).
	h2 := newHarness(t, nil)
	h2.u.init()
	h2.u.saveAttempt(attempt{Version: "0.10.0", From: "0.9.0", AttemptedAt: time.Now()})
	h2.start()
	defer h2.cancel()
	if s := h2.waitState(t, StateFailed); !strings.Contains(s.Error, "msiexec-0.10.0.log") {
		t.Fatalf("stan: %+v", s)
	}
}
