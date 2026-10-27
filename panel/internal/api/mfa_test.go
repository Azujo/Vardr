// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"encoding/base32"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
)

// memMFA: drugi składnik w pamięci (testy).
type memMFA struct {
	mu       sync.Mutex
	st       *memStore
	mfa      map[int64]store.MFA
	codes    map[int64]map[string]bool // skrót → zużyty
	settings map[string]string
	keys     []store.WebAuthnKey
}

func newMemMFA(st *memStore) *memMFA {
	return &memMFA{st: st, mfa: map[int64]store.MFA{}, codes: map[int64]map[string]bool{}, settings: map[string]string{}}
}

func (m *memMFA) MFAState(_ context.Context, id int64) (store.MFA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.mfa[id]
	if !ok {
		return x, store.ErrNotFound
	}
	for _, used := range m.codes[id] {
		if !used {
			x.RecoveryLeft++
		}
	}
	return x, nil
}
func (m *memMFA) MFAEnabledUsers(context.Context) (map[int64]time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int64]time.Time{}
	for id, x := range m.mfa {
		out[id] = x.EnabledAt
	}
	return out, nil
}
func (m *memMFA) EnableMFA(_ context.Context, id int64, sec []byte, step int64, hashes []string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mfa[id] = store.MFA{SecretEnc: sec, EnabledAt: now, LastStep: step}
	m.setCodes(id, hashes)
	return nil
}
func (m *memMFA) setCodes(id int64, hashes []string) {
	m.codes[id] = map[string]bool{}
	for _, h := range hashes {
		m.codes[id][h] = false
	}
}
func (m *memMFA) ReplaceRecoveryCodes(_ context.Context, id int64, hashes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setCodes(id, hashes)
	return nil
}
func (m *memMFA) DisableMFA(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mfa, id)
	delete(m.codes, id)
	m.keys = slices.DeleteFunc(m.keys, func(k store.WebAuthnKey) bool { return k.UserID == id })
	return nil
}
func (m *memMFA) WebAuthnKeys(_ context.Context, id int64) ([]store.WebAuthnKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []store.WebAuthnKey{}
	for _, k := range m.keys {
		if k.UserID == id {
			out = append(out, k)
		}
	}
	return out, nil
}
func (m *memMFA) AddWebAuthnKey(_ context.Context, k store.WebAuthnKey) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.keys {
		if bytes.Equal(x.CredentialID, k.CredentialID) {
			return 0, store.ErrConflict
		}
	}
	k.ID = int64(len(m.keys) + 1)
	m.keys = append(m.keys, k)
	return k.ID, nil
}
func (m *memMFA) UseWebAuthnKey(_ context.Context, id int64, n uint32, uv bool, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, k := range m.keys {
		if k.ID == id && (k.SignCount < n || (k.SignCount == 0 && n == 0)) {
			m.keys[i].SignCount, m.keys[i].UV, m.keys[i].LastUsedAt = n, k.UV || uv, &now
			return true, nil
		}
	}
	return false, nil
}
func (m *memMFA) DeleteWebAuthnKey(_ context.Context, uid, id int64) (store.WebAuthnKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, k := range m.keys {
		if k.ID == id && k.UserID == uid {
			m.keys = slices.Delete(m.keys, i, i+1)
			return k, nil
		}
	}
	return store.WebAuthnKey{}, store.ErrNotFound
}
func (m *memMFA) WebAuthnCounts(context.Context) (map[int64]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int64]int{}
	for _, k := range m.keys {
		out[k.UserID]++
	}
	return out, nil
}
func (m *memMFA) AdvanceMFAStep(_ context.Context, id, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x := m.mfa[id]
	if x.LastStep >= step {
		return false, nil
	}
	x.LastStep = step
	m.mfa[id] = x
	return true, nil
}
func (m *memMFA) UseRecoveryCode(_ context.Context, id int64, h string, _ time.Time) (bool, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	used, ok := m.codes[id][h]
	if !ok || used {
		return false, 0, nil
	}
	m.codes[id][h] = true
	left := 0
	for _, u := range m.codes[id] {
		if !u {
			left++
		}
	}
	return true, left, nil
}
func (m *memMFA) MarkSessionMFA(_ context.Context, id string) error {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	s := m.st.sessions[id]
	s.MFA = true
	m.st.sessions[id] = s
	return nil
}
func (m *memMFA) Setting(_ context.Context, k string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.settings[k]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}
func (m *memMFA) SetSetting(_ context.Context, k, v, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings[k] = v
	return nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newMFAEnv(t *testing.T, policy string) (*env, *memMFA) {
	e := &env{t: t, clock: time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)}
	e.st = newMemStore(func() time.Time { return e.clock })
	m := newMemMFA(e.st)
	if policy != "" {
		m.settings[mfaPolicyKey] = policy
	}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), UI: fstest.MapFS{"index.html": {Data: []byte("x")}},
		MFA: m, MFAKey: []byte(strings.Repeat("k", 32))}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	return e, m
}

// Polityka „wszyscy”: pierwsze logowanie konfiguruje aplikację (QR, kod),
// kolejne wymaga kodu; kod nie działa dwa razy; kod zapasowy – raz.
func TestMFALoginFlow(t *testing.T) {
	e, _ := newMFAEnv(t, "")
	e.addUser("adam", store.RoleAnalyst, "bardzo-tajne-haslo-1", false)
	c := e.client("10.0.0.1")
	code, out, _ := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "adam", "password": "bardzo-tajne-haslo-1"})
	if code != 200 || out["mfa"] != "enroll" || c.cookie != nil {
		t.Fatalf("logowanie bez MFA przy polityce: %d %v", code, out)
	}
	ch := out["challenge"].(string)
	code, setup, _ := c.do("POST", "/api/v1/auth/mfa/enroll", map[string]string{"challenge": ch})
	if code != 200 || !strings.HasPrefix(setup["qr"].(string), "data:image/png") {
		t.Fatalf("konfiguracja: %d %v", code, setup)
	}
	secret, _ := b32.DecodeString(strings.ReplaceAll(setup["secret"].(string), " ", ""))
	if code, _, _ := c.do("POST", "/api/v1/auth/mfa/enroll/confirm", map[string]string{"challenge": ch, "code": "000000"}); code != 401 {
		t.Fatalf("zły kod konfiguracji: %d", code)
	}
	code, out, _ = c.do("POST", "/api/v1/auth/mfa/enroll/confirm", map[string]string{"challenge": ch, "code": auth.TOTPCode(secret, e.clock)})
	if code != 200 || c.cookie == nil || out["mfa"] != true || len(out["recovery_codes"].([]any)) != 10 {
		t.Fatalf("potwierdzenie: %d %v", code, out)
	}
	recovery := out["recovery_codes"].([]any)[0].(string)
	c.csrf = out["csrf_token"].(string)
	if code, out, _ := c.do("GET", "/api/v1/auth/session", nil); code != 200 || out["mfa"] != true {
		t.Fatalf("sesja z MFA: %d %v", code, out)
	}

	// Drugie logowanie: kod; ten sam kod drugi raz – nie.
	d := e.client("10.0.0.2")
	_, out, _ = d.do("POST", "/api/v1/auth/login", map[string]string{"username": "adam", "password": "bardzo-tajne-haslo-1"})
	if out["mfa"] != "code" {
		t.Fatalf("drugie logowanie: %v", out)
	}
	if code, _, _ := d.do("POST", "/api/v1/auth/mfa", map[string]string{"challenge": out["challenge"].(string), "code": auth.TOTPCode(secret, e.clock)}); code != 401 {
		t.Fatalf("ten sam kod drugi raz: %d", code)
	}
	e.clock = e.clock.Add(30 * time.Second)
	if code, _, _ := d.do("POST", "/api/v1/auth/mfa", map[string]string{"challenge": out["challenge"].(string), "code": auth.TOTPCode(secret, e.clock)}); code != 200 || d.cookie == nil {
		t.Fatalf("logowanie kodem: %d", code)
	}
	// Kod zapasowy – raz.
	for i, want := range []int{200, 401} {
		f := e.client("10.0.0.3")
		_, out, _ = f.do("POST", "/api/v1/auth/login", map[string]string{"username": "adam", "password": "bardzo-tajne-haslo-1"})
		code, res, _ := f.do("POST", "/api/v1/auth/mfa", map[string]string{"challenge": out["challenge"].(string), "code": strings.ToUpper(recovery)})
		if code != want || (i == 0 && res["recovery_left"] != float64(9)) {
			t.Fatalf("kod zapasowy #%d: %d %v", i+1, code, res)
		}
	}
	// Po 5 złych kodach logowanie trzeba zacząć od nowa.
	g := e.client("10.0.0.4")
	_, out, _ = g.do("POST", "/api/v1/auth/login", map[string]string{"username": "adam", "password": "bardzo-tajne-haslo-1"})
	for range 5 {
		g.do("POST", "/api/v1/auth/mfa", map[string]string{"challenge": out["challenge"].(string), "code": "111111"})
	}
	if code, res, _ := g.do("POST", "/api/v1/auth/mfa", map[string]string{"challenge": out["challenge"].(string), "code": auth.TOTPCode(secret, e.clock.Add(30*time.Second))}); code != 401 || res["error"] != "mfa_expired" {
		t.Fatalf("po 5 próbach: %d %v", code, res)
	}
}

// Włączenie wymogu odcina sesje bez drugiego składnika; administrator nie
// włączy wymogu, nie mając sam MFA w sesji; reset MFA przez administratora.
func TestMFAPolicy(t *testing.T) {
	e, m := newMFAEnv(t, mfaNone)
	admin := e.addUser("admin", store.RoleAdmin, "bardzo-tajne-haslo-1", false)
	e.addUser("ola", store.RoleViewer, "bardzo-tajne-haslo-2", false)
	a := e.client("10.0.0.1")
	if code, _ := a.login("admin", "bardzo-tajne-haslo-1"); code != 200 {
		t.Fatalf("logowanie bez MFA przy polityce none: %d", code)
	}
	o := e.client("10.0.0.2")
	o.login("ola", "bardzo-tajne-haslo-2")
	if code, out, _ := a.do("PUT", "/api/v1/settings/security", map[string]string{"mfa_policy": "all", "password": "bardzo-tajne-haslo-1"}); code != 400 || out["error"] != "enroll_first" {
		t.Fatalf("wymóg bez własnego MFA: %d %v", code, out)
	}
	// Administrator włącza MFA na swoim koncie.
	_, setup, _ := a.do("POST", "/api/v1/account/mfa/setup", map[string]string{"password": "bardzo-tajne-haslo-1"})
	secret, _ := b32.DecodeString(strings.ReplaceAll(setup["secret"].(string), " ", ""))
	if code, out, _ := a.do("POST", "/api/v1/account/mfa/confirm", map[string]string{"code": auth.TOTPCode(secret, e.clock)}); code != 200 || len(out["recovery_codes"].([]any)) != 10 {
		t.Fatalf("włączenie MFA: %d %v", code, out)
	}
	if code, _, _ := a.do("PUT", "/api/v1/settings/security", map[string]string{"mfa_policy": "admins", "password": "bardzo-tajne-haslo-1"}); code != 200 {
		t.Fatalf("polityka admins: %d", code)
	}
	if code, _, _ := o.do("GET", "/api/v1/auth/session", nil); code != 200 {
		t.Fatalf("obserwator przy polityce admins: %d", code)
	}
	a.do("PUT", "/api/v1/settings/security", map[string]string{"mfa_policy": "all", "password": "bardzo-tajne-haslo-1"})
	if code, out, _ := o.do("GET", "/api/v1/auth/session", nil); code != 401 || out["error"] != "mfa_required" {
		t.Fatalf("sesja bez MFA po włączeniu wymogu: %d %v", code, out)
	}
	if code, _, _ := a.do("GET", "/api/v1/auth/session", nil); code != 200 {
		t.Fatalf("sesja administratora z MFA: %d", code)
	}
	// Reset MFA administratora przez niego samego (np. inny admin) – konto bez MFA, sesje usunięte.
	if code, _, _ := a.do("POST", "/api/v1/users/"+itoa(admin.ID)+"/mfa/reset", map[string]string{"password": "bardzo-tajne-haslo-1"}); code != 200 {
		t.Fatalf("reset MFA: %d", code)
	}
	if _, err := m.MFAState(context.Background(), admin.ID); err == nil {
		t.Fatal("MFA po resecie")
	}
	for _, want := range []string{"mfa_enabled", "mfa_policy_changed", "mfa_reset"} {
		found := false
		for _, x := range e.st.actions() {
			found = found || x == want
		}
		if !found {
			t.Errorf("brak wpisu audytu %s: %v", want, e.st.actions())
		}
	}
}
