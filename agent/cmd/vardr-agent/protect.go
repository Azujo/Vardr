// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"siem/agent/internal/guard"
	"siem/agent/internal/managed"
	"siem/agent/internal/status"
	"siem/internal/contract"
	"siem/internal/lang"
)

// svcGuard: ochrona agenta w procesie usługi (nil w trybie konsoli).
var svcGuard *guardian

// guardian pilnuje uprawnień i konfiguracji usługi, zapisuje zdarzenia
// ochrony i ustala powód zatrzymania (guard – opis całości).
type guardian struct {
	dir string
	log *slog.Logger

	agentID  atomic.Pointer[string]
	cfg      atomic.Pointer[contract.AgentConfig] // konfiguracja z panelu (nil – brak: ochrona wyłączona)
	expected guard.ServiceConfig                  // konfiguracja usługi, która uruchomiła agenta
	stopping atomic.Pointer[string]

	mu     sync.Mutex
	state  string // protected | open | inne SDDL
	errMsg string
}

func newGuardian(dir string, log *slog.Logger) *guardian {
	g := &guardian{dir: dir, log: log}
	if c, err := guard.ReadConfig(serviceName); err == nil {
		c.StartType = 0
		g.expected = c
	}
	return g
}

// startup: wykrycie zabicia poprzedniego procesu i zużycie znacznika
// odblokowania (start po instalacji, aktualizacji albo zatrzymaniu tokenem).
func (g *guardian) startup() {
	prev, err := guard.MarkRunning(g.dir, guard.BootTime())
	if err != nil {
		g.log.Warn("agent protection: writing the running marker failed", "err", err)
	}
	if prev != nil {
		g.record(contract.TamperRecord{Kind: contract.TamperUncleanExit,
			Detail: fmt.Sprintf(lang.L("poprzedni proces agenta (PID %d, start %s UTC) zakończył się bez zatrzymania usługi – zabity albo awaria",
				"the previous agent process (PID %d, started %s UTC) ended without stopping the service – killed or crashed"),
				prev.PID, prev.Started.UTC().Format("2006-01-02 15:04:05"))})
	}
	if u, _ := guard.ReadUnlock(g.dir); u != nil {
		guard.RemoveUnlock(g.dir)
		_ = guard.RecordState(g.dir, guard.StateOpen) // otwarte legalnie – ochrona wróci bez alarmu
	}
}

func (g *guardian) setAgent(id string) { g.agentID.Store(&id) }

func (g *guardian) setConfig(c *contract.AgentConfig) { g.cfg.Store(c) }

func (g *guardian) enabled() bool {
	c := g.cfg.Load()
	return c != nil && c.Limits.ProtectionOn()
}

func (g *guardian) record(r contract.TamperRecord) {
	r, err := guard.Append(g.dir, r)
	level := contract.TamperKinds[r.Kind].Level
	args := []any{"kind", r.Kind, "detail", r.Detail, "user", r.User, "token", r.TokenID, "eventlog", level != ""}
	if err != nil {
		g.log.Error("agent protection: recording the event failed", append(args, "err", err)...)
		return
	}
	if level != "" {
		g.log.Warn("agent protection: "+contract.TamperKinds[r.Kind].TitleEn, args...)
	} else {
		g.log.Info("agent protection: "+contract.TamperKinds[r.Kind].TitleEn, args...)
	}
}

// run pilnuje ochrony co 30 s (pierwszy raz od razu).
func (g *guardian) run(ctx context.Context) {
	for {
		g.enforce(time.Now().UTC())
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

func (g *guardian) setState(state string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state, g.errMsg = state, ""
	if err != nil {
		g.state, g.errMsg = "error", err.Error()
	}
}

func (g *guardian) enforce(now time.Time) {
	acl, err := guard.ServiceACL(serviceName)
	if err != nil {
		g.setState("", err)
		return
	}
	if u, _ := guard.ReadUnlock(g.dir); u.Fresh(now) {
		g.setState(acl, nil) // polecenie z tokenem albo instalator właśnie działa
		return
	}
	recorded := guard.RecordedState(g.dir)
	if !g.enabled() {
		if acl != guard.StateOpen {
			if err := guard.SetServiceACL(serviceName, guard.StateOpen); err != nil {
				g.setState(acl, err)
				return
			}
			_ = guard.RecordState(g.dir, guard.StateOpen)
			if recorded == guard.StateProtected {
				g.record(contract.TamperRecord{Kind: contract.TamperProtectionOff, Detail: lang.L("uprawnienia usługi przywrócone do zwykłych", "service permissions restored to the ordinary ones")})
			}
			acl = guard.StateOpen
		}
		g.setState(acl, nil)
		return
	}
	if acl != guard.StateProtected {
		if recorded == guard.StateProtected {
			what := lang.L("zwykłe uprawnienia (jak po instalacji)", "ordinary permissions (as after installation)")
			if acl != guard.StateOpen {
				what = acl
			}
			g.record(contract.TamperRecord{Kind: contract.TamperACL, Detail: lang.L("uprawnienia usługi zmienione z zewnątrz: ", "service permissions changed from outside: ") + what})
		}
		if err := guard.SetServiceACL(serviceName, guard.StateProtected); err != nil {
			g.setState(acl, err)
			return
		}
		_ = guard.RecordState(g.dir, guard.StateProtected)
		acl = guard.StateProtected
	}
	if g.expected.BinaryPath != "" {
		diffs, err := guard.CheckConfig(serviceName, g.expected, true)
		if len(diffs) > 0 {
			g.record(contract.TamperRecord{Kind: contract.TamperConfig, Detail: strings.Join(diffs, "; ")})
		}
		if err != nil {
			g.setState(acl, fmt.Errorf(lang.L("konfiguracja usługi: %w", "service configuration: %w"), err))
			return
		}
	}
	g.setState(acl, nil)
}

// probe uzupełnia status o stan ochrony.
func (g *guardian) probe(s *status.Status) {
	now := time.Now().UTC()
	g.mu.Lock()
	p := contract.ProtectionStatus{Enabled: g.enabled(), Service: g.state, Error: g.errMsg}
	g.mu.Unlock()
	if p.Service != guard.StateProtected && p.Service != guard.StateOpen && p.Service != "error" && p.Service != "" {
		p.Service = "other"
	}
	if c := g.cfg.Load(); c != nil {
		used := guard.Used(g.dir)
		for _, t := range c.UninstallTokens {
			if !used[t.ID] && (t.ExpiresAt.IsZero() || now.Before(t.ExpiresAt)) {
				p.Tokens++
			}
		}
	}
	p.Events, _ = guard.Recent(g.dir, now)
	s.Protection = &p
}

// stopReason ustala powód zatrzymania usługi i zapisuje zdarzenie ochrony.
func (g *guardian) stopReason() string {
	now := time.Now().UTC()
	u, _ := guard.ReadUnlock(g.dir)
	if !u.Fresh(now) {
		u = nil
	}
	rec := contract.TamperRecord{Kind: contract.TamperStop}
	switch {
	case u != nil && (u.Action == "upgrade" || u.Action == "install"):
		rec = contract.TamperRecord{Kind: contract.TamperUpgrade, User: u.User, Detail: lang.L("zatrzymanie przez instalator (", "stopped by the installer (") + u.Action + ")"}
		if u.Token != "" {
			if t, err := g.verify(u.Token, now); err == nil {
				rec.TokenID, rec.Detail = t.ID, lang.L("aktualizacja tokenem", "upgrade with a token")
			}
		}
	case u != nil:
		t, err := g.verify(u.Token, now)
		switch {
		case err == nil && u.Action == "uninstall":
			rec = contract.TamperRecord{Kind: contract.TamperUninstallTok, User: u.User, TokenID: t.ID}
		case err == nil:
			rec = contract.TamperRecord{Kind: contract.TamperStopToken, User: u.User, TokenID: t.ID}
		default:
			rec.User, rec.Detail = u.User, lang.L("znacznik odblokowania bez ważnego tokenu: ", "unlock marker without a valid token: ")+err.Error()
		}
	case !g.enabled():
		return contract.TamperStop // ochrona wyłączona – bez wpisu (alarmuje utrata łączności)
	default:
		rec.Detail = lang.L("zatrzymanie z pominięciem tokenu (konto SYSTEM albo zmienione uprawnienia usługi)", "stop bypassing the token (SYSTEM account or changed service permissions)")
	}
	g.record(rec)
	return rec.Kind
}

// verify sprawdza token z znacznika odblokowania (polecenie oznaczyło go już
// jako użyty). Polecenie z tokenem pobrało przed chwilą świeżą konfigurację
// z panelu (managed.json), a usługa może mieć jeszcze poprzednią – wtedy
// drugie sprawdzenie z pliku. Plik może podmienić administrator, dlatego
// detektor sprawdza, czy token wydał panel.
func (g *guardian) verify(token string, now time.Time) (contract.UninstallToken, error) {
	var tokens []contract.UninstallToken
	if c := g.cfg.Load(); c != nil {
		tokens = c.UninstallTokens
	}
	id := ""
	if p := g.agentID.Load(); p != nil {
		id = *p
	}
	t, err := guard.Verify(id, token, tokens, nil, now)
	if err != nil {
		if c, lerr := managed.Load(g.dir); lerr == nil && c != nil {
			t, err = guard.Verify(id, token, c.UninstallTokens, nil, now)
		}
	}
	return t, err
}

func (g *guardian) setStopping(reason string) { g.stopping.Store(&reason) }

func (g *guardian) stoppingReason() string {
	if p := g.stopping.Load(); p != nil {
		return *p
	}
	return ""
}

// cleanExit: usługa zatrzymana w zwykły sposób – bez alarmu o zabiciu procesu.
func (g *guardian) cleanExit() { guard.ClearRunning(g.dir) }
