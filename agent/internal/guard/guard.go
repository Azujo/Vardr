// SPDX-License-Identifier: AGPL-3.0-or-later

// Package guard to ochrona agenta przed zatrzymaniem i deinstalacją
// (roadmapa, sekcja 7 – „utrudnić i wykryć”). Pełnej blokady nie ma:
// administrator może zmienić uprawnienia usługi, a SYSTEM zrobić wszystko.
// Dlatego ochrona składa się z:
//
//   - zawężonych uprawnień usługi (administrator nie zatrzyma jej ani nie
//     usunie poleceniem sc/services.msc),
//   - jednorazowych tokenów deinstalacji z panelu (na komputerze tylko skrót),
//   - dziennika zdarzeń ochrony w katalogu stanu, wysyłanego w heartbeacie
//     (zatrzymanie bez tokenu, zabicie procesu, zmiana uprawnień, zły token).
//
// Pliki (katalog stanu, dostęp tylko SYSTEM i Administratorzy):
//
//	tamper.jsonl   dziennik zdarzeń ochrony (dopisywany przez usługę i polecenia)
//	unlock.json    znacznik odblokowania tokenem albo przez instalator
//	guard.json     stan uprawnień usługi ustawiony przez agenta lub instalator
//	used_tokens    użyte tokeny (jednorazowość także bez łączności z panelem)
//	running.json   znacznik działania procesu (wykrycie zabicia)
package guard

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"siem/internal/contract"
	"siem/internal/lang"
)

const (
	journalFile = "tamper.jsonl"
	unlockFile  = "unlock.json"
	stateFile   = "guard.json"
	usedFile    = "used_tokens"
	runningFile = "running.json"

	// Keep i MaxEvents: ile zdarzeń wysyłać w heartbeacie.
	Keep      = 7 * 24 * time.Hour
	MaxEvents = 50
	// UnlockFresh: jak długo znacznik odblokowania wstrzymuje pilnowanie
	// uprawnień (polecenie z tokenem zatrzymuje albo usuwa usługę).
	UnlockFresh = 2 * time.Minute
)

var journalMu sync.Mutex

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Append dopisuje zdarzenie do dziennika (ID i czas uzupełnia, jeśli puste).
func Append(dir string, r contract.TamperRecord) (contract.TamperRecord, error) {
	if r.ID == "" {
		r.ID = newID()
	}
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	data, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	journalMu.Lock()
	defer journalMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, journalFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return r, err
	}
	_, err = f.Write(append(data, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return r, err
}

// Recent zwraca zdarzenia z ostatnich 7 dni (najwyżej MaxEvents, od
// najstarszego). Dziennik z dużą liczbą starych wpisów jest przycinany.
func Recent(dir string, now time.Time) ([]contract.TamperRecord, error) {
	journalMu.Lock()
	defer journalMu.Unlock()
	path := filepath.Join(dir, journalFile)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []contract.TamperRecord
	lines := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		lines++
		var r contract.TamperRecord
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Kind == "" || now.Sub(r.At) > Keep {
			continue
		}
		out = append(out, r)
	}
	if len(out) > MaxEvents {
		out = out[len(out)-MaxEvents:]
	}
	if lines > 4*MaxEvents && lines > len(out) {
		var b bytes.Buffer
		for _, r := range out {
			line, _ := json.Marshal(r)
			b.Write(append(line, '\n'))
		}
		if os.WriteFile(path+".tmp", b.Bytes(), 0o600) == nil {
			_ = os.Rename(path+".tmp", path)
		}
	}
	return out, nil
}

// Unlock to znacznik legalnego zatrzymania: polecenie z tokenem
// (stop, uninstall), instalator (install) albo aktualizacja (upgrade).
// Usługa przy zatrzymaniu sprawdza token ponownie – sam znacznik bez
// ważnego tokenu nie czyni zatrzymania legalnym (poza install/upgrade,
// po których agent musi wrócić).
type Unlock struct {
	Action string    `json:"action"` // stop | uninstall | upgrade | install
	Token  string    `json:"token,omitempty"`
	User   string    `json:"user,omitempty"`
	At     time.Time `json:"at"`
}

// WriteUnlock zapisuje znacznik odblokowania.
func WriteUnlock(dir string, u Unlock) error {
	if u.At.IsZero() {
		u.At = time.Now().UTC()
	}
	return writeJSON(filepath.Join(dir, unlockFile), u)
}

// ReadUnlock wczytuje znacznik (nil, gdy go nie ma).
func ReadUnlock(dir string) (*Unlock, error) {
	var u Unlock
	if err := readJSON(filepath.Join(dir, unlockFile), &u); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

// RemoveUnlock usuwa znacznik.
func RemoveUnlock(dir string) { _ = os.Remove(filepath.Join(dir, unlockFile)) }

// Fresh: znacznik świeży (polecenie właśnie zatrzymuje albo usuwa usługę).
func (u *Unlock) Fresh(now time.Time) bool {
	return u != nil && now.Sub(u.At) < UnlockFresh && u.At.Sub(now) < time.Minute
}

// ServiceState to stan uprawnień usługi zapisany przez tego, kto je
// ostatnio legalnie zmienił: „protected” albo „open”. Uprawnienia inne
// niż zapisane oznaczają zmianę z zewnątrz.
type serviceState struct {
	Service string    `json:"service"`
	At      time.Time `json:"at"`
}

// RecordedState zwraca zapisany stan uprawnień usługi ("" – brak zapisu).
func RecordedState(dir string) string {
	var s serviceState
	if readJSON(filepath.Join(dir, stateFile), &s) != nil {
		return ""
	}
	return s.Service
}

// RecordState zapisuje stan uprawnień usługi.
func RecordState(dir, state string) error {
	return writeJSON(filepath.Join(dir, stateFile), serviceState{Service: state, At: time.Now().UTC()})
}

// Used zwraca identyfikatory użytych tokenów.
func Used(dir string) map[string]bool {
	data, _ := os.ReadFile(filepath.Join(dir, usedFile))
	out := map[string]bool{}
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out[l] = true
		}
	}
	return out
}

// MarkUsed dopisuje token do użytych.
func MarkUsed(dir, id string) error {
	f, err := os.OpenFile(filepath.Join(dir, usedFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(id + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Errors weryfikacji tokenu.
var (
	ErrNoTokens   = lang.Errorf("agent nie zna żadnego tokenu deinstalacji – wygeneruj token w panelu (Huginn → agent → Token deinstalacji); agent pobiera go z panelu", "the agent knows no uninstall token – generate a token in the panel (Huginn → agent → Uninstall token); the agent fetches it from the panel")
	ErrBadToken   = lang.Errorf("niepoprawny token deinstalacji", "invalid uninstall token")
	ErrUsedToken  = lang.Errorf("ten token został już użyty – wygeneruj nowy w panelu", "this token has already been used – generate a new one in the panel")
	ErrExpToken   = lang.Errorf("token deinstalacji wygasł – wygeneruj nowy w panelu", "the uninstall token has expired – generate a new one in the panel")
	ErrNoTokenArg = lang.Errorf("agent jest chroniony – podaj token deinstalacji z panelu: -token XXXXX-XXXXX-XXXXX-XXXXX", "the agent is protected – provide the uninstall token from the panel: -token XXXXX-XXXXX-XXXXX-XXXXX")
)

// Verify sprawdza token względem skrótów z panelu. used – tokeny już
// użyte (nil = bez sprawdzania, np. usługa weryfikująca token, który
// polecenie przed chwilą oznaczyło jako użyty).
func Verify(agentID, token string, tokens []contract.UninstallToken, used map[string]bool, now time.Time) (contract.UninstallToken, error) {
	if strings.TrimSpace(token) == "" {
		return contract.UninstallToken{}, ErrNoTokenArg
	}
	if len(tokens) == 0 {
		return contract.UninstallToken{}, ErrNoTokens
	}
	h := contract.UninstallHash(agentID, token)
	for _, t := range tokens {
		if t.Hash != h {
			continue
		}
		switch {
		case used[t.ID]:
			return t, ErrUsedToken
		case !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt):
			return t, ErrExpToken
		}
		return t, nil
	}
	return contract.UninstallToken{}, ErrBadToken
}

// Running to znacznik działającego procesu agenta. Zostaje po zabiciu
// procesu (usługa nie usunęła go przy zatrzymaniu).
type Running struct {
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	Boot    time.Time `json:"boot"` // start systemu (odróżnia zabicie od utraty zasilania)
}

// MarkRunning zapisuje znacznik działania. Zwraca poprzedni znacznik, jeśli
// został po procesie z tego samego uruchomienia systemu (proces zakończył
// się bez zatrzymania usługi – zabity albo awaria).
func MarkRunning(dir string, boot time.Time) (prev *Running, err error) {
	path := filepath.Join(dir, runningFile)
	var old Running
	if readJSON(path, &old) == nil && sameBoot(old.Boot, boot) {
		prev = &old
	}
	return prev, writeJSON(path, Running{PID: os.Getpid(), Started: time.Now().UTC(), Boot: boot.UTC()})
}

// ClearRunning usuwa znacznik (zatrzymanie usługi albo zamknięcie systemu).
func ClearRunning(dir string) { _ = os.Remove(filepath.Join(dir, runningFile)) }

func sameBoot(a, b time.Time) bool {
	d := a.Sub(b)
	return d > -2*time.Minute && d < 2*time.Minute
}

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", data, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
