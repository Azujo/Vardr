// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"siem/agent/internal/guard"
	"siem/internal/contract"
	"siem/internal/lang"
)

// Ochrona agenta Linux (guard – opis całości). Root może wszystko, więc
// tak jak w Windows chodzi o „utrudnić i wykryć”:
//
//   - drop-in usługi z RefuseManualStop=yes – systemctl stop i restart
//     odmawiają, zatrzymanie tylko poleceniem agenta z tokenem z panelu,
//   - SIGTERM spoza zadania zatrzymania systemd (kill, systemctl kill) jest
//     ignorowany i trafia do dziennika ochrony; SIGKILL – Restart=always
//     uruchamia agenta ponownie, a ten zgłasza zabicie procesu,
//   - co 30 s sprawdzenie usługi: plik jednostki (przywracany), start
//     z systemem (przywracany), maskowanie i obce drop-iny (zgłaszane).
//
// Katalog drop-inów i plik jednostki są zapisywalne dla usługi
// (ReadWritePaths) – reszta /etc pozostaje tylko do odczytu.
const (
	dropInDir     = "/etc/systemd/system/" + unitName + ".d"
	protectDropIn = dropInDir + "/50-vardr-protect.conf"
	protectConf   = `# Vardr: ochrona agenta – zatrzymanie i deinstalacja tylko tokenem z panelu:
#   sudo vardr-agent stop -token XXXXX-XXXXX-XXXXX-XXXXX
# Plik zapisuje i usuwa agent (ochrona włączana w grupie agentów w panelu).
[Unit]
RefuseManualStop=yes
`
	// limitsDropIns: drop-iny limitów z panelu (systemctl set-property --runtime).
	limitsDropIns = "/run/systemd/system.control/" + unitName + ".d/"
)

// serviceWatch: zmiany usługi zgłoszone w tym procesie (bez powtórzeń co 30 s).
type serviceWatch struct {
	reported map[string]bool
}

func stopBypassDetail() string {
	return lang.L("zatrzymanie z pominięciem tokenu (ochrona usługi zdjęta z zewnątrz albo zmiana celu systemd, np. systemctl isolate)",
		"stop bypassing the token (service protection removed from outside or a systemd target change, e.g. systemctl isolate)")
}

func newGuardian(dir string, log *slog.Logger) *guardian {
	return &guardian{dir: dir, log: log, watch: serviceWatch{reported: map[string]bool{}}}
}

// serviceProtection: stan ochrony usługi według systemd (installed=false –
// brak usługi).
func serviceProtection() (state string, installed bool, err error) {
	if _, err := os.Stat(unitPath); err != nil {
		return "", false, nil
	}
	v, err := systemctl("show", "-p", "RefuseManualStop", "--value", unitName)
	if err != nil {
		return "", true, err
	}
	if v == "yes" {
		return guard.StateProtected, true, nil
	}
	return guard.StateOpen, true, nil
}

// setProtection zapisuje albo usuwa drop-in ochrony i przeładowuje systemd.
func setProtection(on bool) error {
	if on {
		if err := os.MkdirAll(dropInDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(protectDropIn, []byte(protectConf), 0o644); err != nil {
			return err
		}
	} else if err := os.Remove(protectDropIn); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_, err := systemctl("daemon-reload")
	return err
}

// openService zdejmuje ochronę (polecenie z tokenem, instalator).
func openService() error { return setProtection(false) }

func (g *guardian) enforce(now time.Time) {
	st, installed, err := serviceProtection()
	if err != nil {
		g.setState("", err)
		return
	}
	if u, _ := guard.ReadUnlock(g.dir); u.Fresh(now) {
		g.setState(st, nil) // polecenie z tokenem albo instalator właśnie działa
		return
	}
	if !installed {
		// Plik jednostki usunięty przy działającej usłudze – przywrócenie.
		if g.enabled() {
			if diffs := g.checkUnit(); len(diffs) > 0 {
				g.record(contract.TamperRecord{Kind: contract.TamperConfig, Detail: strings.Join(diffs, "; ")})
			}
		}
		if st, installed, err = serviceProtection(); err != nil || !installed {
			g.setState("", errors.New(lang.L("brak pliku usługi ", "no service file ")+unitPath))
			return
		}
	}
	recorded := guard.RecordedState(g.dir)
	if !g.enabled() {
		if st != guard.StateOpen {
			if err := setProtection(false); err != nil {
				g.setState(st, err)
				return
			}
			_ = guard.RecordState(g.dir, guard.StateOpen)
			if recorded == guard.StateProtected {
				g.record(contract.TamperRecord{Kind: contract.TamperProtectionOff, Detail: lang.L("usunięto drop-in ochrony usługi (RefuseManualStop)", "the service protection drop-in (RefuseManualStop) was removed")})
			}
			st = guard.StateOpen
		}
		g.setState(st, nil)
		return
	}
	if st != guard.StateProtected {
		if recorded == guard.StateProtected {
			g.record(contract.TamperRecord{Kind: contract.TamperACL, Detail: lang.L("ochrona usługi (RefuseManualStop w "+protectDropIn+") zdjęta z zewnątrz – przywrócona",
				"service protection (RefuseManualStop in "+protectDropIn+") removed from outside – restored")})
		}
		if err := setProtection(true); err != nil {
			g.setState(st, fmt.Errorf(lang.L("włączenie ochrony usługi: %w", "enabling service protection: %w"), err))
			return
		}
		_ = guard.RecordState(g.dir, guard.StateProtected)
		if st, _, err = serviceProtection(); err == nil && st != guard.StateProtected {
			g.setState(st, errors.New(lang.L("systemd nie przyjął RefuseManualStop (inny drop-in nadpisuje ochronę?)", "systemd did not accept RefuseManualStop (another drop-in overrides the protection?)")))
			return
		}
		st = guard.StateProtected
	}
	if diffs := g.checkUnit(); len(diffs) > 0 {
		g.record(contract.TamperRecord{Kind: contract.TamperConfig, Detail: strings.Join(diffs, "; ")})
	}
	g.setState(st, nil)
}

// checkUnit porównuje usługę z instalacją agenta: przywraca plik jednostki
// i start z systemem, zgłasza maskowanie i obce drop-iny. Zwraca zmiany
// jeszcze niezgłoszone w tym procesie.
func (g *guardian) checkUnit() []string {
	var diffs []string
	note := func(key, text string) {
		if !g.watch.reported[key] {
			g.watch.reported[key] = true
			diffs = append(diffs, text)
		}
	}
	reload := false
	if data, err := os.ReadFile(unitPath); err != nil || string(data) != unitFile {
		what := lang.L("plik usługi "+unitPath+" zmieniony", "service file "+unitPath+" changed")
		if err != nil {
			what = lang.L("plik usługi "+unitPath+" usunięty", "service file "+unitPath+" removed")
		}
		if werr := os.WriteFile(unitPath, []byte(unitFile), 0o644); werr != nil {
			note("unit:"+werr.Error(), what+lang.L(" – nie przywrócono: ", " – not restored: ")+werr.Error())
		} else {
			reload = true
			delete(g.watch.reported, "unit")
			diffs = append(diffs, what+lang.L(" – przywrócony", " – restored"))
		}
	}
	if reload {
		if _, err := systemctl("daemon-reload"); err != nil {
			note("reload", "daemon-reload: "+err.Error())
		}
	}
	props, err := unitProps("UnitFileState", "LoadState", "FragmentPath", "DropInPaths")
	if err != nil {
		note("show:"+err.Error(), "systemctl show: "+err.Error())
		return diffs
	}
	if props["LoadState"] == "masked" || props["UnitFileState"] == "masked" || props["UnitFileState"] == "masked-runtime" {
		note("masked", lang.L("usługa zamaskowana (systemctl mask) – nie wystartuje po restarcie systemu", "service masked (systemctl mask) – it will not start after a system restart"))
	} else {
		delete(g.watch.reported, "masked")
	}
	if fp := props["FragmentPath"]; fp != "" && fp != unitPath {
		note("fragment:"+fp, lang.L("systemd czyta usługę z innego pliku: ", "systemd reads the service from another file: ")+fp)
	}
	switch props["UnitFileState"] {
	case "enabled", "masked", "masked-runtime":
	default:
		state := props["UnitFileState"]
		if _, err := systemctl("enable", unitName); err != nil {
			note("enable:"+state, lang.L("usługa wyłączona ze startu systemu (", "service disabled from system start (")+state+lang.L(") – nie przywrócono: ", ") – not restored: ")+err.Error())
		} else {
			diffs = append(diffs, lang.L("usługa wyłączona ze startu systemu (", "service disabled from system start (")+state+lang.L(") – włączona ponownie", ") – enabled again"))
		}
	}
	for _, p := range strings.Fields(props["DropInPaths"]) {
		if p == protectDropIn || strings.HasPrefix(p, limitsDropIns) {
			continue
		}
		note("dropin:"+p, lang.L("dodatkowa konfiguracja usługi (drop-in): ", "additional service configuration (drop-in): ")+p)
	}
	return diffs
}

// unitProps: właściwości usługi z systemctl show.
func unitProps(names ...string) (map[string]string, error) {
	out, err := systemctl("show", unitName, "-p", strings.Join(names, ","))
	if err != nil {
		return nil, err
	}
	props := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && slices.Contains(names, k) {
			props[k] = v
		}
	}
	return props, nil
}

// systemStopping: system jest zamykany albo uruchamiany ponownie.
func systemStopping() bool {
	out, _ := systemctl("is-system-running")
	return out == "stopping"
}

// onTerm rozstrzyga sygnał zakończenia: zatrzymanie przez systemd (stop,
// zamknięcie systemu) kończy agenta z powodem; sygnał wysłany z pominięciem
// systemd przy włączonej ochronie jest ignorowany i zapisany.
func (g *guardian) onTerm(sig os.Signal) (reason string, stop bool) {
	if systemStopping() {
		return "shutdown", true
	}
	if active, err := systemctl("show", "-p", "ActiveState", "--value", unitName); err != nil || active != "active" && active != "reloading" {
		return g.stopReason(), true // zadanie zatrzymania (deactivating) albo stan nieznany
	}
	if u, _ := guard.ReadUnlock(g.dir); !g.enabled() || u.Fresh(time.Now().UTC()) {
		return g.stopReason(), true
	}
	g.record(contract.TamperRecord{Kind: contract.TamperBadToken,
		Detail: fmt.Sprintf(lang.L("sygnał %v wysłany do procesu agenta z pominięciem systemd (kill albo systemctl kill) – zignorowany, agent działa dalej",
			"signal %v sent to the agent process bypassing systemd (kill or systemctl kill) – ignored, the agent keeps running"), sig)})
	return "", false
}
