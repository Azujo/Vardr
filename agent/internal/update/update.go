// SPDX-License-Identifier: AGPL-3.0-or-later

// Package update to automatyczna aktualizacja agenta z panelu (1.7.0).
// Konfiguracja grupy z włączonymi aktualizacjami podaje wersję, rozmiar
// i sumę SHA-256 instalatora MSI z serwera. Agent starszy niż ta wersja –
// po losowym opóźnieniu (rozłożenie pobrań w czasie) – pobiera instalator
// z panelu przez mTLS, sprawdza sumę i uruchamia msiexec. Instalator
// zatrzymuje usługę, podmienia program i uruchamia nową wersję z tą samą
// rejestracją (jak aktualizacja przez GPO). Próba jest zapisana w
// update.json w katalogu stanu: nowa wersja po starcie zgłasza powodzenie,
// a nieudana próba danej wersji powtarza się najwcześniej po Retry.
//
// Agent Linux (1.9.0) pobiera tak samo program dla swojej architektury
// (Path), a podmianę wykonuje Install (usługa systemd – main).
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"siem/internal/contract"
	"siem/internal/lang"
)

// Stany aktualizacji (status agenta → panel).
const (
	StateWaiting    = "waiting"    // czeka na losowe opóźnienie albo ponowienie
	StateInstalling = "installing" // msiexec uruchomiony
	StateFailed     = "failed"
	StateDone       = "done" // nowa wersja działa
)

// Status to stan aktualizacji widoczny w panelu.
type Status struct {
	Target string    `json:"target"`
	State  string    `json:"state"`
	Error  string    `json:"error,omitempty"` // StateWaiting: błąd poprzedniej próby
	At     time.Time `json:"at"`
	From   string    `json:"from,omitempty"` // wersja przed aktualizacją (StateDone)
}

// attempt to zapis próby w update.json.
type attempt struct {
	Version     string    `json:"version"`
	From        string    `json:"from"`
	AttemptedAt time.Time `json:"attempted_at"`
	Error       string    `json:"error,omitempty"`
}

const stateFile = "update.json"

// Updater pobiera i instaluje nowszą wersję agenta.
type Updater struct {
	Client   *http.Client // klient mTLS agenta
	PanelURL string
	Dir      string // katalog stanu agenta (tylko administratorzy i SYSTEM)
	Version  string // wersja działającego agenta
	Log      *slog.Logger
	Warn     func(string) // trwałe ostrzeżenie w statusie (może być nil)
	Report   func(Status) // stan dla panelu (może być nil)
	MaxDelay time.Duration
	Retry    time.Duration
	// Path: endpoint panelu z pakietem (domyślnie instalator MSI).
	Path string
	// Install uruchamia pobrany pakiet i zwraca funkcję czekającą na koniec
	// instalatora (nil – instalator systemu, np. msiexec).
	Install func(pkg, logPath string) (wait func() error, err error)

	install func(pkg, logPath string) (wait func() error, err error)
	now     func() time.Time
	offers  chan *contract.AgentUpdate
	once    sync.Once
}

// init przygotowuje pola (Offer można wołać przed Run, z innej gorutyny).
func (u *Updater) init() { u.once.Do(u.setup) }

func (u *Updater) setup() {
	if u.offers == nil {
		u.offers = make(chan *contract.AgentUpdate, 1)
	}
	if u.install == nil {
		u.install = u.Install
	}
	if u.install == nil {
		u.install = startInstaller
	}
	if u.Path == "" {
		u.Path = contract.AgentMSIPath
	}
	if u.now == nil {
		u.now = time.Now
	}
	if u.MaxDelay < 0 {
		u.MaxDelay = 0
	}
	if u.Retry <= 0 {
		u.Retry = 6 * time.Hour
	}
}

// Offer przekazuje aktualizację z konfiguracji (nil – brak); nie blokuje,
// nowsza oferta zastępuje oczekującą.
func (u *Updater) Offer(up *contract.AgentUpdate) {
	u.init()
	select {
	case <-u.offers:
	default:
	}
	u.offers <- up
}

func (u *Updater) dir() string { return filepath.Join(u.Dir, "update") }

func (u *Updater) loadAttempt() (attempt, error) {
	var a attempt
	data, err := os.ReadFile(filepath.Join(u.Dir, stateFile))
	if err != nil {
		return a, err
	}
	return a, json.Unmarshal(data, &a)
}

func (u *Updater) saveAttempt(a attempt) error {
	data, _ := json.Marshal(a)
	tmp := filepath.Join(u.Dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(u.Dir, stateFile))
}

func (u *Updater) report(s Status) {
	if u.Report != nil {
		u.Report(s)
	}
}

func (u *Updater) warn(msg string) {
	if u.Warn != nil {
		u.Warn(msg)
	}
}

// checkPrevious po starcie: czy poprzednia próba się udała (działa już
// wersja docelowa) albo nie (agent wrócił w starej wersji).
func (u *Updater) checkPrevious() {
	a, err := u.loadAttempt()
	if err != nil {
		return
	}
	if !contract.NewerVersion(a.Version, u.Version) {
		_ = os.Remove(filepath.Join(u.Dir, stateFile))
		_ = os.RemoveAll(u.dir())
		u.Log.Info("agent updated automatically", "from", a.From, "to", u.Version, "eventlog", true)
		u.report(Status{Target: a.Version, State: StateDone, From: a.From, At: u.now()})
		return
	}
	if a.Error == "" {
		a.Error = lang.L("instalator nie zainstalował nowej wersji – szczegóły w dzienniku ", "the installer did not install the new version – details in the log ") +
			u.logPath(a.Version)
		_ = u.saveAttempt(a)
	}
	u.Log.Warn("previous automatic update failed", "version", a.Version, "err", a.Error, "eventlog", true)
	u.report(Status{Target: a.Version, State: StateFailed, Error: a.Error, At: a.AttemptedAt})
}

func (u *Updater) pkgPath(v string) string { return filepath.Join(u.dir(), "vardr-agent-"+v+pkgSuffix) }
func (u *Updater) logPath(v string) string { return filepath.Join(u.dir(), logPrefix+v+".log") }

// MarkFailed zapisuje błąd próby aktualizacji (proces podmieniający program
// agenta Linux przywrócił poprzednią wersję); agent zgłosi go po starcie.
func MarkFailed(dir, msg string) error {
	u := &Updater{Dir: dir}
	a, err := u.loadAttempt()
	if err != nil {
		return err
	}
	a.Error = msg
	return u.saveAttempt(a)
}

// Pending: czy próba aktualizacji czeka na potwierdzenie nowej wersji
// (update.json usuwa nowa wersja po starcie).
func Pending(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, stateFile))
	return err == nil
}

// Run obsługuje oferty do końca ctx.
func (u *Updater) Run(ctx context.Context) {
	u.init()
	u.checkPrevious()
	var target *contract.AgentUpdate
	var timer *time.Timer
	var fire <-chan time.Time
	var done chan error
	stop := func() {
		if timer != nil {
			timer.Stop()
		}
		fire = nil
	}
	schedule := func(d time.Duration) {
		stop()
		timer = time.NewTimer(d)
		fire = timer.C
		s := Status{Target: target.Version, State: StateWaiting, At: u.now().Add(d)}
		if a, err := u.loadAttempt(); err == nil && a.Version == target.Version {
			s.Error = a.Error // ponowienie po nieudanej próbie – błąd zostaje widoczny
		}
		u.report(s)
	}
	for {
		select {
		case <-ctx.Done():
			stop()
			return
		case up := <-u.offers:
			if up == nil || !contract.NewerVersion(up.Version, u.Version) {
				if target != nil {
					u.Log.Info("automatic update withdrawn", "version", target.Version)
					if done == nil {
						u.report(Status{}) // stan „zaplanowana” znika z panelu
					}
				}
				target = nil
				stop()
				continue
			}
			if target != nil && *target == *up {
				continue
			}
			target = up
			if done != nil {
				continue // instalator działa – nowa oferta po jego końcu
			}
			delay := u.retryWait(up)
			if delay == 0 && u.MaxDelay > 0 {
				delay = rand.N(u.MaxDelay)
			}
			u.Log.Info("automatic update scheduled", "from", u.Version, "to", up.Version, "in", delay.Round(time.Second))
			schedule(delay)
		case <-fire:
			fire = nil
			if target == nil || done != nil {
				continue
			}
			if w := u.retryWait(target); w > 0 {
				schedule(w)
				continue
			}
			wait, err := u.attempt(ctx, target)
			if err != nil {
				u.fail(target, err)
				schedule(u.Retry)
				continue
			}
			done = make(chan error, 1)
			go func(ch chan error) { ch <- wait() }(done)
		case err := <-done:
			// Agent nadal działa po końcu instalatora: aktualizacja się nie
			// udała (sukces zatrzymałby usługę i uruchomił nową wersję).
			done = nil
			if err == nil {
				err = errors.New(lang.L("instalator zakończył się bez podmiany agenta", "the installer finished without replacing the agent"))
			}
			if target != nil {
				u.fail(target, fmt.Errorf("%w – %s", err, u.logPath(target.Version)))
				schedule(u.Retry)
			}
		}
	}
}

// retryWait: ile jeszcze czekać na ponowienie nieudanej próby tej wersji.
func (u *Updater) retryWait(up *contract.AgentUpdate) time.Duration {
	a, err := u.loadAttempt()
	if err != nil || a.Version != up.Version {
		return 0
	}
	if w := a.AttemptedAt.Add(u.Retry).Sub(u.now()); w > 0 {
		return w
	}
	return 0
}

func (u *Updater) fail(up *contract.AgentUpdate, err error) {
	a, _ := u.loadAttempt()
	if a.Version != up.Version {
		a = attempt{Version: up.Version, From: u.Version, AttemptedAt: u.now()}
	}
	a.Error = err.Error()
	_ = u.saveAttempt(a)
	u.Log.Error("automatic update failed", "version", up.Version, "err", err, "eventlog", true)
	u.warn(lang.L("aktualizacja do ", "update to ") + up.Version + lang.L(" nieudana: ", " failed: ") + err.Error())
	u.report(Status{Target: up.Version, State: StateFailed, Error: err.Error(), At: u.now()})
}

// attempt pobiera, sprawdza i uruchamia instalator.
func (u *Updater) attempt(ctx context.Context, up *contract.AgentUpdate) (func() error, error) {
	if err := os.MkdirAll(u.dir(), 0o700); err != nil {
		return nil, err
	}
	pkg := u.pkgPath(up.Version)
	if err := u.download(ctx, up, pkg); err != nil {
		return nil, err
	}
	if err := u.saveAttempt(attempt{Version: up.Version, From: u.Version, AttemptedAt: u.now()}); err != nil {
		return nil, err
	}
	u.Log.Info("starting the agent installer", "from", u.Version, "to", up.Version, "eventlog", true)
	u.report(Status{Target: up.Version, State: StateInstalling, At: u.now()})
	return u.install(pkg, u.logPath(up.Version))
}

// download zapisuje instalator, gdy suma i rozmiar zgadzają się z konfiguracją.
func (u *Updater) download(ctx context.Context, up *contract.AgentUpdate, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.PanelURL+u.Path, nil)
	if err != nil {
		return err
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return lang.Errorf("pobranie instalatora: %w", "downloading the installer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return lang.Errorf("pobranie instalatora: HTTP %d: %s", "downloading the installer: HTTP %d: %s", resp.StatusCode, body)
	}
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, up.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return lang.Errorf("pobranie instalatora: %w", "downloading the installer: %w", err)
	}
	if n != up.Size || hex.EncodeToString(h.Sum(nil)) != up.SHA256 {
		_ = os.Remove(tmp)
		return lang.Errorf("instalator z panelu nie zgadza się z sumą SHA-256 z konfiguracji – nie uruchomiono go",
			"the installer from the panel does not match the SHA-256 sum from the configuration – not started")
	}
	return os.Rename(tmp, path)
}
