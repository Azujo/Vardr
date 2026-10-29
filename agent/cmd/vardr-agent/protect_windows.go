// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"siem/agent/internal/guard"
	"siem/internal/contract"
	"siem/internal/lang"
)

// serviceWatch: konfiguracja usługi, która uruchomiła agenta (wzorzec dla
// CheckConfig).
type serviceWatch struct {
	expected guard.ServiceConfig
}

func stopBypassDetail() string {
	return lang.L("zatrzymanie z pominięciem tokenu (konto SYSTEM albo zmienione uprawnienia usługi)", "stop bypassing the token (SYSTEM account or changed service permissions)")
}

func newGuardian(dir string, log *slog.Logger) *guardian {
	g := &guardian{dir: dir, log: log}
	if c, err := guard.ReadConfig(serviceName); err == nil {
		c.StartType = 0
		g.watch.expected = c
	}
	return g
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
	if g.watch.expected.BinaryPath != "" {
		diffs, err := guard.CheckConfig(serviceName, g.watch.expected, true)
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

// serviceProtection: stan uprawnień usługi (installed=false – brak usługi).
func serviceProtection() (state string, installed bool, err error) {
	acl, err := guard.ServiceACL(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf(lang.L("odczyt uprawnień usługi: %w", "reading service permissions: %w"), err)
	}
	return acl, true, nil
}

// openService przywraca zwykłe uprawnienia usługi (polecenie z tokenem).
func openService() error { return guard.SetServiceACL(serviceName, guard.StateOpen) }
